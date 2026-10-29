"""LLM Planner Adapter mediating between untrusted language models and AgentFence gateway.

Untrusted Model Principle:
The model is an untrusted planner. Natural language prompts produce structured tool proposals
matching ActionRequest schemas. Every proposal is deterministically evaluated by the PolicyEngine,
executed only through confined tools / isolated containers, and permanently recorded in SQLite.
API keys are loaded strictly from environment variables, never logged, and never sent to sandboxes.
"""

import json
import os
import re
from typing import Any, Protocol, runtime_checkable

import httpx
from pydantic import BaseModel

from app.api.schemas import ActionResponse
from app.policy.models import ActionRequest
from app.tools.dispatcher import ToolDispatcher

# Standard system prompt supplied to models to enforce structured tool calling
SYSTEM_PROMPT = """You are an AI planner connected to the AgentFence security gateway.
Your job is to translate the user's natural language goal into exactly ONE structured tool action.

You MUST respond with a single, valid JSON object matching this exact schema:
{
  "tool": "<tool_name>",
  "arguments": {
    <argument_key>: <argument_value>
  }
}

AVAILABLE TOOLS:
1. "list_files": List contents of a directory in the workspace.
   Arguments:
   - "path" (string, optional, defaults to "."): Directory relative to workspace.

2. "read_file": Read the text content of a workspace file.
   Arguments:
   - "path" (string, required): File path relative to workspace.

3. "write_file": Write text content to a file in the workspace.
   Arguments:
   - "path" (string, required): File path relative to workspace.
   - "content" (string, required): Text content to write.

4. "delete_file": Delete a file in the workspace (pauses for human operator approval).
   Arguments:
   - "path" (string, required): File path relative to workspace.

5. "run_command": Execute an allowed command inside the isolated sandbox container.
   Allowed commands: python3, pytest, ls, cat, echo, grep, head, tail, wc.
   Arguments:
   - "command" (string, required): Plain command executable name (e.g. "python3", "pytest").
   - "args" (array of strings, optional): Command line arguments array.
   - "timeout" (integer, optional): Maximum execution seconds (max 30).

CRITICAL RULES:
- Output ONLY the JSON object. Do not include markdown explanation, code fences, or conversation.
- If the user asks for a host file (e.g. /etc/passwd), propose it; policy enforces containment.
- Never propose shell pipelines or unlisted commands.
"""


def extract_json_payload(raw_text: str) -> dict[str, Any]:
    """Safely extract and parse a JSON dictionary from an LLM response string."""
    text = raw_text.strip()

    # Strip markdown code fences (```json ... ``` or ``` ... ```)
    if text.startswith("```"):
        lines = text.splitlines()
        if len(lines) >= 2 and lines[-1].strip() == "```":
            text = "\n".join(lines[1:-1]).strip()
        elif lines[0].startswith("```"):
            text = "\n".join(lines[1:]).strip()

    # Attempt direct JSON parse
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    # Find outermost curly braces if surrounded by prose
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidate = text[start : end + 1]
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

    raise ValueError(
        f"Unable to extract valid JSON dictionary from model response: {raw_text[:200]}"
    )


class PlanResult(BaseModel):
    """Encapsulates the end-to-end outcome of an LLM planning and dispatch step."""

    prompt: str
    provider: str
    action: ActionRequest
    response: ActionResponse
    raw_model_output: str | None = None
    fallback_used: bool = False


@runtime_checkable
class LLMProvider(Protocol):
    """Protocol for LLM planner providers."""

    @property
    def provider_name(self) -> str: ...

    def generate_action(self, prompt: str) -> tuple[ActionRequest, str]:
        """Generate a structured ActionRequest and raw output text from user prompt."""
        ...


class DeterministicFallbackProvider:
    """Heuristic fallback planner used when no external API key is configured.

    Ensures the gateway is 100% testable and runnable offline without external services.
    """

    @property
    def provider_name(self) -> str:
        return "mock_fallback"

    def generate_action(self, prompt: str) -> tuple[ActionRequest, str]:
        prompt_lower = prompt.lower().strip()

        # 1. Path traversal / absolute path / adversarial canary requests
        match_path = re.search(
            r"(/[a-zA-Z0-9_\.\-]+(?:/[a-zA-Z0-9_\.\-]+)+|\.\./[a-zA-Z0-9_\.\-/]+)",
            prompt,
        )
        if match_path:
            path_val = match_path.group(1).rstrip(".,;'\"")
            tool_name = "delete_file" if "delete" in prompt_lower else "read_file"
            req = ActionRequest(tool=tool_name, arguments={"path": path_val})
            return req, json.dumps(req.model_dump())

        # 2. File writing commands
        if "write" in prompt_lower or "create file" in prompt_lower:
            match_to = re.search(r"\bto\s+([a-zA-Z0-9_\-\./]+)", prompt, re.I)
            match_file = re.search(
                r"(?:write|create file)\s+(?:file\s+)?([a-zA-Z0-9_\-\./]+)", prompt, re.I
            )
            target = (
                match_to.group(1)
                if match_to
                else (match_file.group(1) if match_file else "output.txt")
            )
            content = "Generated content"
            match_content = re.search(r"['\"]([^'\"]+)['\"]", prompt)
            if match_content:
                content = match_content.group(1)
            req = ActionRequest(tool="write_file", arguments={"path": target, "content": content})
            return req, json.dumps(req.model_dump())

        # 3. File deletion commands
        if "delete" in prompt_lower or "remove" in prompt_lower:
            match = re.search(
                r"(?:delete|remove)\s+(?:the\s+)?(?:host\s+)?(?:file\s+)?([a-zA-Z0-9_\-\./]+)",
                prompt,
                re.I,
            )
            target = match.group(1) if match else "obsolete.txt"
            req = ActionRequest(tool="delete_file", arguments={"path": target})
            return req, json.dumps(req.model_dump())

        # 4. File reading commands
        if "read" in prompt_lower or "cat " in prompt_lower:
            match = re.search(
                r"(?:read|cat|inspect)\s+(?:the\s+)?(?:host\s+)?(?:file\s+)?([a-zA-Z0-9_\-\./]+)",
                prompt,
                re.I,
            )
            target = match.group(1) if match else "README.md"
            req = ActionRequest(tool="read_file", arguments={"path": target})
            return req, json.dumps(req.model_dump())

        # 5. Inspect workspace / directory listing
        if (
            "workspace" in prompt_lower
            or "list" in prompt_lower
            or "directory" in prompt_lower
            or prompt_lower in ("ls", "dir")
        ):
            req = ActionRequest(tool="list_files", arguments={"path": "."})
            return req, json.dumps(req.model_dump())

        # 4. File writing commands
        if "write" in prompt_lower or "create file" in prompt_lower:
            match_file = re.search(r"(?:write|create file)\s+(?:to\s+)?([^\s,;]+)", prompt, re.I)
            target = match_file.group(1) if match_file else "output.txt"
            content = "Generated content"
            match_content = re.search(r"['\"]([^'\"]+)['\"]", prompt)
            if match_content:
                content = match_content.group(1)
            req = ActionRequest(tool="write_file", arguments={"path": target, "content": content})
            return req, json.dumps(req.model_dump())

        # 5. Command execution
        if "run" in prompt_lower or "execute" in prompt_lower or "test" in prompt_lower:
            if "pytest" in prompt_lower:
                req = ActionRequest(
                    tool="run_command", arguments={"command": "pytest", "args": ["-v"]}
                )
            elif "python" in prompt_lower or "python3" in prompt_lower:
                req = ActionRequest(
                    tool="run_command",
                    arguments={"command": "python3", "args": ["-c", "print('hello from python')"]},
                )
            elif "curl" in prompt_lower:
                req = ActionRequest(
                    tool="run_command",
                    arguments={"command": "curl", "args": ["http://1.1.1.1"]},
                )
            else:
                req = ActionRequest(
                    tool="run_command",
                    arguments={"command": "ls", "args": ["-la"]},
                )
            return req, json.dumps(req.model_dump())

        # 6. Default to list_files
        req = ActionRequest(tool="list_files", arguments={"path": "."})
        return req, json.dumps(req.model_dump())


class GeminiProvider:
    """Live planner adapter for Google Gemini models via REST API."""

    DEFAULT_MODEL = "gemini-1.5-flash"

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        timeout: float = 15.0,
    ) -> None:
        self._api_key = api_key or os.environ.get("GEMINI_API_KEY")
        if not self._api_key:
            raise ValueError("GEMINI_API_KEY environment variable is not set")
        self.model = model or self.DEFAULT_MODEL
        self.timeout = timeout

    @property
    def provider_name(self) -> str:
        return f"gemini ({self.model})"

    def __repr__(self) -> str:
        # Never leak API key in string representation
        return f"GeminiProvider(model={self.model}, api_key=***)"

    def generate_action(self, prompt: str) -> tuple[ActionRequest, str]:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self._api_key}"
        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {
                            "text": (
                                f"User Goal: {prompt}\n\n"
                                "Propose exactly one structured tool action to satisfy this goal."
                            )
                        }
                    ],
                }
            ],
            "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
            "generationConfig": {
                "responseMimeType": "application/json",
                "temperature": 0.0,
            },
        }

        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, json=payload)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            raise RuntimeError(f"Gemini API request failed: {exc}") from exc

        try:
            candidates = data.get("candidates", [])
            raw_text = candidates[0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError) as exc:
            raise RuntimeError(f"Malformed response structure from Gemini API: {data}") from exc

        parsed_json = extract_json_payload(raw_text)
        action_req = ActionRequest.model_validate(parsed_json)
        return action_req, raw_text


class OpenAIProvider:
    """Live planner adapter for OpenAI models via REST API."""

    DEFAULT_MODEL = "gpt-4o-mini"

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        timeout: float = 15.0,
    ) -> None:
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not self._api_key:
            raise ValueError("OPENAI_API_KEY environment variable is not set")
        self.model = model or self.DEFAULT_MODEL
        self.timeout = timeout

    @property
    def provider_name(self) -> str:
        return f"openai ({self.model})"

    def __repr__(self) -> str:
        # Never leak API key in string representation
        return f"OpenAIProvider(model={self.model}, api_key=***)"

    def generate_action(self, prompt: str) -> tuple[ActionRequest, str]:
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.0,
        }

        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            raise RuntimeError(f"OpenAI API request failed: {exc}") from exc

        try:
            raw_text = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as exc:
            raise RuntimeError(f"Malformed response structure from OpenAI API: {data}") from exc

        parsed_json = extract_json_payload(raw_text)
        action_req = ActionRequest.model_validate(parsed_json)
        return action_req, raw_text


class LLMPlanner:
    """Coordinates untrusted model planning with deterministic gateway authorization.

    1. Receives natural language user goal or prompt.
    2. Dispatches prompt to configured LLM provider (Gemini, OpenAI, or deterministic fallback).
    3. Validates model output against Pydantic ActionRequest schema (Untrusted Model Principle).
    4. Routes validated action through ToolDispatcher.dispatch() choke point.
    """

    def __init__(
        self,
        dispatcher: ToolDispatcher,
        provider: str | LLMProvider | None = None,
        api_key: str | None = None,
        model: str | None = None,
        fallback_on_missing_key: bool = True,
    ) -> None:
        self.dispatcher = dispatcher
        self._provider_inst, self.is_fallback = self._resolve_provider(
            provider=provider,
            api_key=api_key,
            model=model,
            fallback_on_missing_key=fallback_on_missing_key,
        )

    @property
    def provider_name(self) -> str:
        return self._provider_inst.provider_name

    def _resolve_provider(
        self,
        provider: str | LLMProvider | None,
        api_key: str | None,
        model: str | None,
        fallback_on_missing_key: bool,
    ) -> tuple[LLMProvider, bool]:
        """Resolve the appropriate LLM provider with graceful fallback."""
        if isinstance(provider, LLMProvider) or (
            hasattr(provider, "generate_action") and not isinstance(provider, str)
        ):
            return provider, False

        provider_choice = str(provider).lower() if provider else "auto"

        if provider_choice == "gemini":
            try:
                return GeminiProvider(api_key=api_key, model=model), False
            except ValueError:
                if fallback_on_missing_key:
                    return DeterministicFallbackProvider(), True
                raise

        if provider_choice == "openai":
            try:
                return OpenAIProvider(api_key=api_key, model=model), False
            except ValueError:
                if fallback_on_missing_key:
                    return DeterministicFallbackProvider(), True
                raise

        if provider_choice == "mock" or provider_choice == "fallback":
            return DeterministicFallbackProvider(), True

        # Auto-detect: check environment variables
        if os.environ.get("GEMINI_API_KEY"):
            return GeminiProvider(api_key=api_key, model=model), False

        if os.environ.get("OPENAI_API_KEY"):
            return OpenAIProvider(api_key=api_key, model=model), False

        # Graceful fallback when no keys are found
        return DeterministicFallbackProvider(), True

    def plan(self, prompt: str) -> tuple[ActionRequest, str]:
        """Ask model provider to generate structured tool action for user prompt."""
        try:
            return self._provider_inst.generate_action(prompt)
        except Exception as exc:
            # Untrusted model failure: fall back to safe unknown_tool action
            raw_err = f"Model generation error: {exc}"
            return ActionRequest(tool="unknown_tool", arguments={"error": raw_err}), raw_err

    def plan_and_dispatch(self, prompt: str, is_async: bool = False) -> PlanResult:
        """Formulate action from prompt and dispatch through deterministic gateway."""
        action_req, raw_output = self.plan(prompt)

        # Gateway Choke Point: evaluate and execute
        action_res = self.dispatcher.dispatch(action_req, is_async=is_async)

        return PlanResult(
            prompt=prompt,
            provider=self.provider_name,
            action=action_req,
            response=action_res,
            raw_model_output=raw_output,
            fallback_used=self.is_fallback,
        )
