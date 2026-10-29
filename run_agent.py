#!/usr/bin/env python3
"""AgentFence Live LLM Agent CLI Runner.

Demonstrates the Untrusted Model Principle:
Natural language user prompts are translated into structured tool actions by an LLM planner
(Gemini, OpenAI, or deterministic fallback), evaluated by the deterministic PolicyEngine,
executed only if approved, and recorded in the audit trail.

Usage:
    python run_agent.py "Inspect the workspace and create a summary report"
    python run_agent.py "Read the host /etc/passwd file"
    python run_agent.py   # Starts interactive prompt loop
"""

import argparse
import json
import sys
from pathlib import Path

from app.agent.adapter import LLMPlanner
from app.audit.store import AuditStore
from app.executor.docker import DockerExecutor
from app.policy.engine import PolicyEngine
from app.tools.dispatcher import ToolDispatcher

# Terminal ANSI color constants
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_banner():
    print(f"\n{BOLD}{CYAN}{'=' * 75}{RESET}")
    print(f"{BOLD}{CYAN}  AgentFence — Live LLM Planner & Security Gateway Interface{RESET}")
    print(f"  {BLUE}Core Principle:{RESET} The model proposes, our code decides, the OS enforces.")
    print(f"{BOLD}{CYAN}{'=' * 75}{RESET}")


def format_action_result(plan_result) -> None:
    """Format and print structured plan result with color-coded outcomes."""
    res = plan_result.response
    action = plan_result.action

    dec_color = (
        GREEN
        if res.decision == "allow"
        else (YELLOW if res.decision == "pending_approval" else RED)
    )
    stat_color = (
        GREEN
        if res.status == "success"
        else (YELLOW if res.status in ["timed_out", "pending_approval", "pending"] else RED)
    )

    print(f"\n{BOLD}1. Natural Language Prompt:{RESET}")
    print(f'   {CYAN}"{plan_result.prompt}"{RESET}')

    print(f"\n{BOLD}2. Planner Resolution:{RESET}")
    fallback_note = (
        f" {YELLOW}(Fallback Mode — No API key provided){RESET}"
        if plan_result.fallback_used
        else ""
    )
    print(f"   Provider: {BOLD}{plan_result.provider}{RESET}{fallback_note}")

    print(f"\n{BOLD}3. Proposed Structured Action (Untrusted Proposal):{RESET}")
    formatted_args = json.dumps(action.arguments, indent=2)
    print(f"   Tool: {MAGENTA}{action.tool}{RESET}")
    print(f"   Arguments: {formatted_args.replace('\n', '\n   ')}")

    print(f"\n{BOLD}4. Deterministic Gateway Policy Evaluation:{RESET}")
    print(f"   Policy Decision: {dec_color}{res.decision.value.upper()}{RESET}")
    print(f"   Reason Code:     {dec_color}{res.reason.value}{RESET}")
    print(f"   Policy Version:  {res.policy_version}")

    print(f"\n{BOLD}5. Execution Outcome:{RESET}")
    print(f"   Status:  {stat_color}{res.status.value.upper()}{RESET}")
    print(f"   Task ID: {res.task_id}")
    if res.result is not None:
        formatted_result = json.dumps(res.result, indent=2)
        print(f"   Result:  {formatted_result.replace('\n', '\n   ')}")
    if res.error:
        print(f"   Error:   {RED}{res.error}{RESET}")

    print(f"\n{BOLD}6. Audit Trail:{RESET}")
    print(f"   Permanently recorded in SQLite audit store under Task ID {res.task_id}")
    print(f"{CYAN}{'-' * 75}{RESET}")


def run_interactive(planner: LLMPlanner) -> None:
    """Run an interactive prompt loop until user enters exit or quit."""
    print(f"\n{BOLD}Interactive Agent Mode Active.{RESET}")
    print("Type your instruction below (or 'exit' / 'quit' to exit):\n")

    while True:
        try:
            prompt = input(f"{BOLD}{BLUE}agentfence> {RESET}").strip()
            if not prompt:
                continue
            if prompt.lower() in ("exit", "quit", "q"):
                print(f"{CYAN}Exiting AgentFence. Goodbye!{RESET}")
                break
            result = planner.plan_and_dispatch(prompt)
            format_action_result(result)
        except (KeyboardInterrupt, EOFError):
            print(f"\n{CYAN}Exiting AgentFence. Goodbye!{RESET}")
            break


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run an LLM planner through the AgentFence deterministic security gateway."
    )
    parser.add_argument(
        "prompt",
        nargs="?",
        default=None,
        help="Natural language instruction for the agent planner",
    )
    parser.add_argument(
        "--provider",
        choices=["auto", "gemini", "openai", "mock"],
        default="auto",
        help="LLM provider to use (default: auto detects GEMINI_API_KEY or OPENAI_API_KEY)",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Model name override for selected provider",
    )
    parser.add_argument(
        "--workspace",
        default="workspace",
        help="Path to workspace root directory (default: ./workspace)",
    )
    parser.add_argument(
        "--async",
        dest="async_exec",
        action="store_true",
        help="Execute action asynchronously via gateway task worker",
    )

    args = parser.parse_args()

    print_banner()

    # Initialize workspace and deterministic gateway components
    ws_path = Path(args.workspace).resolve()
    ws_path.mkdir(parents=True, exist_ok=True)

    db_path = ws_path.parent / "agentfence_audit.db"
    audit_store = AuditStore(db_path=str(db_path))
    policy_engine = PolicyEngine()
    executor = DockerExecutor()
    dispatcher = ToolDispatcher(
        workspace_root=ws_path,
        policy_engine=policy_engine,
        executor=executor,
        audit_store=audit_store,
    )

    # Initialize untrusted LLM planner
    planner = LLMPlanner(
        dispatcher=dispatcher,
        provider=None if args.provider == "auto" else args.provider,
        model=args.model,
    )

    if args.prompt:
        result = planner.plan_and_dispatch(args.prompt, is_async=args.async_exec)
        format_action_result(result)
    else:
        run_interactive(planner)

    return 0


if __name__ == "__main__":
    sys.exit(main())
