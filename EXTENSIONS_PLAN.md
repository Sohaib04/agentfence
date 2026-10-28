# AgentFence — Extensions & Side Quests Plan

> **Companion specification to [AGENTFENCE_IMPLEMENTATION_PLAN.md](AGENTFENCE_IMPLEMENTATION_PLAN.md).**  
> Covers optional follow-on capabilities (Section 9) broken into isolated, testable side quest milestones.

---

## 0. Ground Rules & Principles (Mandatory)

1. **Core Preservation:** Never break or weaken the guarantees established in Milestones 1–4. The gateway must remain 100% testable without live API keys or external services.
2. **Untrusted Model Principle:** The model is an untrusted planner. Model outputs are untrusted proposals that must always be validated by Pydantic schemas, evaluated by the deterministic policy engine, and executed through isolated tools.
3. **One Side Quest at a Time:** Complete each side quest in full, verify it with tests and Ruff, and stop for a manual git commit before proceeding to the next.
4. **No Direct Push:** The developer commits and pushes manually; the agent never executes `git push`.
5. **Quality Verification:** Every side quest must include automated tests in `tests/`, pass `pytest -v`, and pass `ruff check .` and `ruff format --check .`.

---

## Side Quest 1: Real LLM Adapter (Untrusted Planner)

**Goal:** Connect a real LLM provider (e.g., Gemini, OpenAI, or Claude) to act as a live planner that formulates structured tool actions from natural language user prompts.

### Scope:
- Create `app/agent/adapter.py` providing a clean `LLMPlanner` interface:
  - Takes a user goal or instruction (e.g., *"Inspect the workspace and create a summary report"*).
  - Supplies the model with tool definitions matching AgentFence's schemas.
  - Enforces structured tool-calling / JSON output.
  - Passes proposed action to `ToolDispatcher.dispatch()`.
- API key loaded strictly from environment variable (e.g., `GEMINI_API_KEY` or `OPENAI_API_KEY`).
  - **Never hardcoded, never logged, never committed, and never mounted into the sandbox container.**
- Fallback / Mock mode: if no API key is provided, gracefully falls back to deterministic behavior or reports clean error without crashing.
- Interactive CLI demo: `python run_agent.py "User prompt"`.

### Done When:
- A real user prompt generates a structured action, runs through policy checks, and executes if allowed.
- Adversarial user prompt (e.g., *"Read the host /etc/passwd file"*) causes the LLM to propose an action that the gateway intercepts, blocks, and audits.
- Unit and integration tests verify the adapter using mocks when no API key is present in CI.

---

## Side Quest 2: Empirical Attack-Success-Rate (ASR) Benchmark

**Goal:** Quantify and demonstrate the security gateway's efficacy by running a benchmark suite of adversarial prompts against a live model.

### Scope:
- Create `benchmarks/asr_benchmark.py`:
  - Curated dataset of prompt-injection and jailbreak attacks (e.g., indirect injection in files, roleplay jailbreaks, path traversal requests).
  - Runs the scenarios through the LLM planner with and without AgentFence gateway mediation.
- Generates reproducible metrics:
  - Attack Success Rate (ASR) without gateway.
  - Attack Success Rate (ASR) with AgentFence gateway (**Target: 0% breach rate**).
- Outputs a clean terminal summary table and markdown report for the README.

### Done When:
- Benchmark runs deterministically over the scenario set.
- Reports real numbers: total scenarios, allowed benign actions, blocked attacks, and 0% host escape rate.

---

## Side Quest 3: Asynchronous / Background Execution & Polling [COMPLETED]

**Goal:** Allow long-running commands (e.g., test suites, compiles) to run asynchronously without blocking client HTTP requests.

### Scope:
- Update `POST /v1/actions` with an optional `async: bool = False` argument:
  - When `true`, gateway authorizes the action, creates a `TaskRecord` with status `pending`/`running`, spawns execution in a background worker thread, and immediately returns `202 Accepted` with `task_id`.
- Client polls `GET /v1/tasks/{task_id}` to monitor lifecycle transitions (`pending` -> `running` -> `success` / `error` / `timed_out`).
- Audit events recorded at start and completion.
- Bounded concurrency to protect host resources.

### Done When:
- Asynchronous command returns `202 Accepted` immediately.
- Polling `GET /v1/tasks/{task_id}` reflects live status and final result when complete.
- Integration tests verify task transition and timeout handling under async execution.

---

## Side Quest 4: Fine-Grained Human Approval for `delete_file` [COMPLETED]

**Goal:** Implement human-in-the-loop authorization for destructive tools.

### Scope:
- Implement `delete_file` tool in `app/tools/files.py`.
- Update policy configuration to support `approval_required = true` for sensitive tools.
- When an action requires approval:
  - Policy engine returns `decision="pending_approval"`.
  - Task is stored in SQLite with status `pending_approval`.
- Add approval endpoint: `POST /v1/tasks/{task_id}/approve` (and `/reject`).
- Approved task continues through dispatcher; rejected task transitions to `denied`.

### Done When:
- Submitting `delete_file` pauses in `pending_approval`.
- Action cannot execute until approved via API.
- Rejection prevents file deletion and audits the refusal.

---

## Side Quest 5: gVisor (`runsc`) Sandboxing Analysis & Architecture Comparison [COMPLETED]

**Goal:** Evaluate Google's gVisor runtime (`runsc`) as a defense against shared-kernel vulnerabilities.

### Scope:
- Add gVisor runtime configuration options to `DockerExecutor` (`--runtime=runsc`).
- Document the threat model comparison: standard Docker (`runc`) vs gVisor (`runsc`) vs microVMs (Firecracker).
- Provide automated check detecting whether `runsc` is installed on host; if present, run comparative isolation tests.
- Add an architectural analysis section in README documenting kernel isolation tradeoffs.

### Done When:
- Executor supports `--runtime=runsc` when configured.
- Documentation honestly compares container isolation boundaries and kernel attack surface.
