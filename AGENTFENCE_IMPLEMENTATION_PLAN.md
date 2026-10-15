# AgentFence — Implementation Spec

**Read this whole file before doing anything. Then follow "Start Here" at the bottom.**

## 0. Project in One Paragraph

AgentFence is a local security gateway that mediates an AI agent's access to files and command execution. An agent submits structured actions. A deterministic policy engine decides whether each action is allowed. Approved actions run through narrowly defined tools, and any command execution happens inside a restricted Docker container. Every decision and result is recorded in an audit store.

**Core principle:** the agent proposes, our code decides, the operating system enforces. A prompt telling the model to behave is not a security control, and neither is an LLM judging another LLM.

This is a resume project for new-grad SWE roles. It is a small, working reference monitor for one machine, one user, and one workspace, not a way to secure a whole computer. Working, tested, and honest beats big.

**MVP promise:** an agent can read and edit files inside a designated workspace and run approved commands. It cannot use the service to access arbitrary host files, run unrestricted host commands, or exceed configured execution limits.

**Definition of success:** a terminal demo where (1) a legitimate workspace read/write/command succeeds, (2) a forbidden action (path traversal, symlink escape, disallowed command) is denied and audited, and (3) a runaway command is killed on timeout and reported correctly.

---

## 1. Rules of Engagement (Mandatory)

1. **Inspect first.** If a repo exists, read its files, dependencies, and state before changing anything. Don't overwrite working code without a reason.
2. **One milestone at a time.** Within a milestone, one small step at a time. Never generate the whole app in one go.
3. **Stay in scope.** See Non-Goals.
4. **Verify, don't assume.** Only report a feature as done if you ran it. State which commands you ran and whether they passed. Never invent test results, benchmark numbers, or completed features.
5. **Backend only.** No browser, no screenshots, no UI automation, no frontend. Verify with pytest, curl/HTTP requests, CLI, Docker CLI, logs, and exit codes.
6. **Minimal dependencies.** Prefer the standard library. Explain any new dependency before adding it.
7. **No premature infrastructure.** No Kubernetes, cloud deploy, microservices, distributed queues, tracing, ORMs, second databases, or Redis.
8. **Bounded commands.** Always use timeouts and small inputs. No indefinite processes, unbounded loops, long benchmarks, or stress tests on the host.
9. **Protect the host.** No destructive shell commands outside disposable test directories. Never touch the real home directory, real credentials, or unrelated files. Never weaken host or container security to make a test pass.
10. **Explain tradeoffs briefly**, especially what Docker isolation does and does not protect against.
11. **Ask before optional work.** Finish core requirements first; ask before starting anything in Section 9.
12. **Don't guess.** If a detail is unspecified here, or you are unsure about a library, Docker flag, or OS behavior, check the installed version or docs, pick a sensible default, state the assumption, and move on. Do not fabricate APIs, flags, or file contents.
13. **Failures:** investigate the specific failure, fix the root cause, rerun only the relevant tests. Don't rerun the whole suite after every small edit.
14. I want to understand the code. Keep explanations concise and focused on important decisions.

---

## 2. Non-Goals

Not full desktop control (no mouse, screenshots, or keyboard automation). Not unrestricted host terminal access. Not browser automation or arbitrary network access. Not multiple agents with different trust levels. Not distributed, remote, or cloud-hosted. Not a hardened boundary against kernel exploits, container escapes, or a compromised Docker daemon. Not a policy engine that uses an LLM to judge safety. Not a dashboard.

Document these limits honestly in the README.

---

## 3. Stack

Use these unless the existing repo gives a good reason not to.

| Concern | Choice |
|---|---|
| Language | Python 3 (3.12 preferred; use whatever compatible version is installed) |
| API | FastAPI + Uvicorn |
| Schemas | Pydantic |
| Isolation | Docker (external runtime requirement) |
| Persistence | SQLite via stdlib `sqlite3` (no ORM) |
| Tests | Pytest + HTTPX / FastAPI TestClient |
| Lint/format | Ruff |
| CI | GitHub Actions (small, bounded suite) |
| Policy file | One simple config file. Prefer a stdlib-readable format (e.g. TOML or JSON); if YAML is preferred, explain the extra dependency first |

Initial dependencies only: FastAPI, Uvicorn, Pydantic, Pytest, HTTPX, Ruff.

---

## 4. Architecture

Keep the security-critical path small and easy to reason about.

`Agent client → FastAPI gateway → Policy engine → Tool dispatcher → Restricted executor (Docker, for commands) → Audit store (SQLite)`

- **Agent client:** a deterministic mock agent first. An optional real-model adapter comes later (Section 9).
- **Gateway:** schema validation, request size limits, local-client auth token, loopback binding by default. Handlers stay thin; logic lives in separate modules.
- **Policy engine:** trusted, deterministic, independent of FastAPI and of any LLM, so it is testable without either. Checks the tool allowlist, path scope, argument validation, and resource policy. Returns a structured decision with a reason code and policy version. **Fails closed:** if it can't validate an action, it denies.
- **Tool dispatcher:** routes approved actions to narrow tool implementations. **There must be exactly one code path into any tool, and that path always runs policy evaluation first.** No tool may be callable around the policy engine.
- **Restricted executor:** runs approved commands in a locked-down container and owns lifecycle, limits, and cleanup.
- **Audit store:** records both denials and allowed actions.

### Trust boundaries
1. **The model is untrusted.** It can be wrong, follow malicious instructions found in files, or deliberately request prohibited operations. File contents are untrusted data.
2. **The policy engine is trusted application code.** Deterministic, tested, fails closed.
3. **The execution environment enforces limits independently.** Policy alone can't stop a program that was given too much access.

The agent must not have a parallel unrestricted route to host tools. If it can call a separate local shell directly, AgentFence cannot enforce anything over that route. Document this.

### Suggested layout (adjust as needed; create files only when their responsibility is real, no empty placeholders)

```
app/
  api/        routes and schemas
  policy/     deterministic authorization rules
  tools/      file operations and command interface
  executor/   Docker lifecycle and limits
  audit/      SQLite persistence
  agent/      mock agent (+ optional model adapter later)
policies/     default policy config
tests/        unit/, integration/, security/
examples/
Dockerfile.sandbox
README.md, pyproject.toml, .gitignore, .env.example, CI workflow
```

Keep host-side orchestration separate from code running inside the sandbox.

---

## 5. Tools and Policy

Start with a small explicit tool set. Do not start with arbitrary computer control.

| Tool | MVP behavior | Default policy |
|---|---|---|
| `list_files` | List files in the workspace | Allow within scope |
| `read_file` | Read a workspace file | Allow within scope |
| `write_file` | Create/update a workspace file | Allow within scope; log the change |
| `delete_file` | Delete a workspace file | Deny initially (or require explicit approval) |
| `run_command` | Run a supported command in the container | Allow only specific commands and validated arguments |
| `network_request` | External access | Deny by default |
| `open_application` | Launch host apps | Not supported in MVP |

Unknown tools are denied.

Actions are structured, e.g. `{ "tool": "read_file", "arguments": { "path": "src/main.py" } }`. Decisions are structured, e.g. `{ "decision": "deny", "reason": "path_outside_workspace", "policy_version": "1" }`. Exact field names are up to you; **be consistent.**

### Two decisions that matter most

**File access.** Don't check whether a string starts with the workspace path. Resolve paths properly, handle `..` traversal, absolute paths, and symlinks, and be aware of time-of-check/time-of-use races. Safest MVP approach: confine file operations to a dedicated workspace and avoid giving the executor broad host filesystem access. Research the correct approach for the installed Python version rather than guessing.

**Command execution.** Never interpolate model-generated text into a shell string. Accept structured arguments, use an argument array (never `shell=True`), enforce an allowlist, and run inside the restricted environment. Even an allowed executable can be dangerous with arbitrary arguments, so validate arguments too. An allowlist alone does not make a command safe; isolation and limits are still required.

---

## 6. API Contract

Small and coherent. Use Pydantic request/response models, consistent status codes, generated IDs, and never leak internal exceptions, stack traces, host paths, or secrets.

| Endpoint | Purpose |
|---|---|
| `POST /v1/actions` | Validate, authorize, and execute a requested tool action |
| `GET /v1/tasks/{task_id}` | Retrieve task state and outcome (`404` for unknown ID) |
| `GET /v1/audit` | Inspect recorded decisions and results (dev/demo only) |
| `GET /health` | Minimal liveness check; must not run a sandbox |

**Distinct outcomes.** Never collapse these into one response: *denied by policy*, *allowed and succeeded*, *allowed but failed*, *timed out*. A denial is not a runtime error.

**Validation (starting defaults, make configurable):** cap request and script sizes, cap timeouts with a sane default and maximum, cap captured output, reject unknown parameters. **Never accept Docker options, host paths, env vars, or container privileges from the client.**

First version may be synchronous if timeouts are short and cleanup is correct. If later made async, return a task ID rather than building a distributed queue.

**Local API security:** bind to loopback by default and use a local auth token. Loopback binding alone doesn't stop malicious local processes or cross-origin browser requests. Don't expose to the LAN.

**Persist per task:** task ID, timestamps, tool name, validated arguments (sensitive values redacted), policy decision/reason/version, execution status and exit code, bounded stdout/stderr or structured result, and timeout/cancellation/cleanup info. Don't store secrets or full file contents by default. The result must come from the executor; never trust a model-supplied status.

---

## 7. Execution Environment Requirements

For `run_command`, use a dedicated Docker container configured restrictively. Verify each flag against the installed Docker version rather than assuming.

- **Unprivileged:** non-root user, drop unneeded Linux capabilities, `no-new-privileges`, never mount the Docker socket, never use privileged mode.
- **Minimal filesystem:** read-only root filesystem where practical, a dedicated workspace mount, a small temporary writable area. No home directory, no host secrets, no app config mounted.
- **Resource limits:** memory, CPU, process count, wall-clock timeout, output size. A Python-side timeout alone is not enough: the container must actually be killed and cleaned up.
- **Network:** disabled for execution containers. No access to localhost services or internal networks.
- **Hygiene:** pin the sandbox image to a specific version or digest (no silent `latest`), bound concurrent executions, persist task state before and after important lifecycle transitions, and make timeout, cancellation, and failure paths all clean up.

If a Docker feature behaves differently on this machine, **document the limitation instead of silently removing the control.**

---

## 8. Milestones

Build in order. Don't start a milestone until the previous one's completion criteria are met. Don't build later-milestone systems early.

### Milestone 1: Policy engine, file tools, and API skeleton (no Docker yet)
**Goal:** actions are authorized or rejected deterministically, and workspace file tools are safe.

Scope:
- Inspect repo/environment; set up the Python project and dependency config.
- Action and decision schemas; a policy config format; reason codes; policy version.
- Policy engine with fail-closed behavior, independent of FastAPI and LLMs.
- File tools (`list_files`, `read_file`, `write_file`) confined to a workspace, with careful path resolution.
- FastAPI app with `GET /health` and `POST /v1/actions` for file tools, going through a single dispatcher choke point.
- Local auth token and loopback binding.

Done when:
- Allowed workspace actions succeed; unknown tools, invalid schemas, and out-of-scope paths are denied with reason codes.
- `../` traversal, absolute paths, and symlink escapes are blocked.
- No tool is reachable without passing policy evaluation.
- Policy tests run without FastAPI or any LLM.

Testing: policy unit tests first, plus a few focused API tests. **Do not** build the executor, audit store, mock agent, or LLM adapter yet.

### Milestone 2: Restricted executor (`run_command`)
**Goal:** approved commands run in a locked-down container and are contained.

Scope:
- Sandbox Dockerfile (pinned base), executor module, `run_command` tool.
- Command and argument validation with an explicit allowlist; argument arrays only.
- Container hardening per Section 7: unprivileged, no network, limited filesystem, resource limits.
- Timeout handling, output limits, and guaranteed cleanup after success, failure, and timeout.

Done when:
- An allowed command runs and returns executor-collected output.
- A disallowed command or argument never executes.
- A runaway command is stopped within the configured bound and its container is cleaned up.
- Output beyond the limit is truncated safely.
- The container cannot reach the network or files outside its workspace (verified with a harmless canary file).

Testing: a small number of real-Docker integration tests plus mocked unit tests. Skip and clearly report Docker tests if Docker is unavailable.

### Milestone 3: Persistence, audit, and reliability
**Goal:** durable, auditable behavior and predictable failure handling.

Scope:
- SQLite persistence for tasks and audit events (denials and allowed actions).
- `GET /v1/tasks/{task_id}` and `GET /v1/audit`.
- Handling for unknown IDs, executor failures, container startup failure, and database errors.
- Structured logging; consistent error format; no internal details leaked.
- Redaction of sensitive values; no full file contents in audit by default.
- Ruff and a basic CI workflow running the same bounded suite.

Done when:
- Task state survives an API restart.
- Every action, allowed or denied, produces an audit record.
- Failed and timed-out tasks have clear status and cleanup info.
- The suite runs locally with one command, and CI runs the same bounded suite.

Testing: persistence of an allowed task and a denied one, unknown task ID, a failed task, audit retrieval. **Do not** build event sourcing or add a message broker.

### Milestone 4: Mock agent, adversarial scenarios, and polish
**Goal:** a reviewer can reproduce the demo and understand the design in minutes.

Scope:
- Deterministic mock agent with predefined action sequences.
- A small fixed set of adversarial scenarios (see Section 10).
- Short terminal demo script covering the three success scenarios from Section 0.
- README and threat model (Section 11), including honest limitations.
- Verify setup instructions on a clean environment if practical.

Done when:
- A new developer can follow the README and run the demo.
- Adversarial scenarios have reproducible expected outcomes.
- Any numbers reported (test counts, latency, scenario counts) come from actual runs.
- No feature is described as implemented unless it works.

If time is short, cut the optional model adapter before cutting tests or documentation.

---

## 9. Optional Work (only after all milestones are complete; ask first)

Priority order:
1. **One real LLM adapter**, treated as an untrusted planner. The model proposes a structured action, which is schema-validated, then sent through the policy engine, then executed only if approved. API key via environment variable, never committed and never sent into the sandbox. The project must remain fully testable without it via the mock agent.
2. Measure attack-success rates across a fixed scenario set with a real model, reported with scenario counts.
3. Background execution via a simple worker returning a task ID.
4. `delete_file` with an explicit approval flow.
5. gVisor comparison against baseline Docker config.

Don't add extensions just to lengthen a tech list. Each new tool expands the attack surface and needs its own threat model and tests.

---

## 10. Testing Policy (Mandatory)

Goal: enough confidence for a resume project, not exhaustive verification.

**Target coverage (a compact suite; one test may cover several bullets):**
- *Policy unit:* unknown tool, invalid schema, forbidden path, disallowed command, missing permission.
- *Filesystem attacks:* `../` traversal, absolute paths, symlink escape, attempts to overwrite outside the workspace.
- *Runtime limits:* infinite loop/timeout, excessive output, memory pressure, process creation limits.
- *Prompt-injection scenario:* a workspace file contains malicious instructions, and the mock agent then requests a forbidden read. Verify (1) the policy denies it, (2) the contents are never returned, (3) the denial is in the audit log, (4) a later legitimate workspace read still succeeds. Test the enforcement layer, not whether a model recognizes the attack.
- *Failure and cleanup:* container startup failure, executor crash, timeout, cancellation, database error.
- *End to end:* legitimate tasks succeed, denied tasks never execute, decisions and results are auditable.

**Rules:**
- Mocks for ordinary unit tests; real Docker for a small number of integration tests.
- After a small change, run only relevant tests. Run the full suite at milestone completion.
- Short per-test timeouts, small inputs, bounded output.
- Destructive filesystem, process-exhaustion, and resource-limit tests run **only** in disposable temp directories or containers. Use a harmless canary file; never real credentials, SSH keys, or the real home directory.
- No long stress tests, no repeated runs for nicer numbers, no external-network dependencies.
- If Docker is unavailable, skip Docker integration tests, say so clearly, and **do not claim sandbox security was verified.**
- Aim for a suite that finishes in tens of seconds (excluding setup); not a hard requirement.

**Allowed verification tools:** `pytest`, `ruff check .`, `ruff format --check .`, `curl`, small Python scripts, Docker CLI, logs, exit codes. **No** browser automation, screenshots, or visual checks.

---

## 11. README and Threat Model Requirements

README: project overview; architecture and request flow; features (**only implemented and tested ones**); prerequisites; setup, run, and test commands; API examples; demo walkthrough; real test counts and results; limitations; realistic future work.

Threat model section: assets (host files outside the workspace, integrity of unauthorized files, host OS, CPU/memory/process/disk capacity, audit integrity); the three trust boundaries from Section 4; a threat-to-defense-to-test table covering prompt injection via files, path traversal, symlinks, arbitrary commands, runaway processes, memory exhaustion, network exfiltration, request flooding, and executor crashes; and honest limits: Docker shares the host kernel, so this is not a hardened boundary against kernel exploits, container escapes, or a compromised Docker daemon.

---

## 12. Definition of Done

- API starts and exposes the documented endpoints.
- Every action passes through one policy-checked path.
- Workspace file tools are confined; traversal and symlink escapes are blocked and tested.
- Approved commands run in the restricted container; disallowed ones never execute.
- Resource, time, output, and network limits are enforced and tested.
- Cleanup works after success, failure, and timeout.
- Allowed and denied actions are both persisted and auditable.
- Compact test suite passes; CI runs it.
- Terminal demo works with no frontend.
- README includes the threat model and honest limitations.
- No credentials or unnecessary generated files in the repo.
- Every claim made about the project is backed by the actual implementation.

---

## 13. Start Here

1. Inspect the repository and environment. Check whether Python and Docker are available.
2. Summarize the current project state and any missing prerequisites.
3. Propose the smallest implementation step for Milestone 1.
4. Wait for my go-ahead, then implement only that step without touching unrelated files.
5. Run only the focused tests needed to verify it.
6. Report what changed, which commands you ran (and results), and what's next.

**Do not** generate every file up front, install a large set of dependencies, run a large test suite, or start optional work before the core flow works. If there's a real design decision, explain the tradeoff and recommend a practical default.
