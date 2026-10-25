# AgentFence

> **Deterministic local security gateway mediating AI agent tool access and command execution.**

AgentFence acts as a local reference monitor between an untrusted AI agent and a machine's operating system. The agent proposes structured tool actions, a deterministic policy engine evaluates each action against a strict security policy, approved actions run through confined tools and an isolated Docker sandbox, and all actions and outcomes are recorded in an audit store.

**Core Principle:** *The agent proposes, our code decides, the operating system enforces.* A prompt instructing a model to behave is not a security control, and neither is an LLM judging another LLM.

---

## Architecture & Request Flow

```
Agent Client
     │  (Structured JSON Action)
     ▼
FastAPI Gateway (Loopback-bound, token authentication, request size cap)
     │
     ▼
Policy Engine (Deterministic authorization, fail-closed, no LLMs)
     │
     ├──[ DENIED ]──► Record Denial in SQLite Audit Store ──► Return Status "denied"
     │
     └──[ ALLOWED ]─► Tool Dispatcher (Single Choke Point)
                           │
             ┌─────────────┴─────────────┐
             ▼                           ▼
     Confined File Tools        Restricted Executor
     (Path containment,         (Docker sandbox, unprivileged user,
      symlink escape check)      --network none, --read-only root,
             │                   memory/pids/cpus/timeout limits)
             └─────────────┬─────────────┘
                           │
                           ▼
                  SQLite Audit Store
                  (Immutable audit events, redacted credentials & file bodies)
```

### Trust Boundaries
1. **The Model is Untrusted:** The agent or LLM can be hallucinating, compromised by prompt injection inside workspace files, or actively attempting prohibited operations. File contents are untrusted data.
2. **The Policy Engine is Trusted Application Code:** Completely deterministic, tested independently of FastAPI or LLMs, and fails closed on any unhandled exception or parsing failure.
3. **The Execution Environment Enforces Isolation Independently:** Policy rules alone cannot stop a runaway or memory-intensive program once launched; container resource limits and kernel namespaces enforce containment.

*Note on Architecture Integrity:* AgentFence requires that all agent interactions flow through the gateway. If an agent retains a parallel, unrestricted terminal or host API route, AgentFence cannot enforce controls over that route.

---

## Features (Implemented & Verified)

- **Deterministic Policy Engine:** Pure Python authorization engine with reason codes (`allowed`, `unknown_tool`, `tool_disabled`, `invalid_arguments`, `path_outside_workspace`, `symlink_escape`, `file_too_large`, `disallowed_command`).
- **Workspace Path Confinement:** Strict normalization and resolution blocking path traversals (`../`), host root escapes (`/etc/passwd`), and intermediate or leaf symlink escapes.
- **Single Choke-Point Tool Dispatcher:** Ensures no tool is ever executed without policy approval. Distinctly reports `success`, `error`, `denied`, and `timed_out` without collapsing outcomes.
- **Safe File Tools:** `list_files`, `read_file`, and `write_file` confined to a workspace with 1MB size bounds and automated parent directory creation.
- **Restricted Docker Executor:** Executes approved commands inside an unprivileged container:
  - `--network none` (zero network access, verified via canary)
  - `--read-only` root filesystem with minimal `/tmp` tmpfs
  - `--cap-drop ALL` and `--security-opt no-new-privileges`
  - Non-root user (`10001:10001`)
  - Bounded memory (256MB), CPU (1.0), and processes (`pids-limit 64`)
  - Guaranteed container termination (`docker rm -f`) on wall-clock timeout
  - Safe output decoding with byte caps and `[OUTPUT TRUNCATED]` tagging
- **Crash-Resilient SQLite Audit Store:**
  - Standard library `sqlite3` (no heavy ORMs).
  - Persists full task lifecycle and immutable audit log surviving cold restarts.
  - Automatic redaction of credentials (`token`, `auth`, `password`, `key`, `secret`).
  - Suppression of full file bodies in audit logs to protect data privacy.
- **Local API Gateway:** FastAPI loopback-bound (`127.0.0.1:8000`) with token authentication, 2MB request body cap, and safe error masking (no leaked stack traces or host paths).
- **Deterministic Mock Agent & Adversarial Test Suite:** Reproducible simulation of indirect prompt injection and attack sequences.

---

## Threat Model

### Protected Assets
- **Host Filesystem:** Host files outside the workspace (e.g. `/etc`, SSH keys, user home directory).
- **File Integrity:** Unauthorized modification or deletion of host files.
- **Host Resources:** CPU, memory, process table capacity, and disk space against runaway processes.
- **Network Boundaries:** Localhost services, LAN devices, and external internet from exfiltration.
- **Audit Integrity:** Accurate, tamper-evident recording of allowed and denied actions.

### Threat-to-Defense-to-Test Matrix

| Threat | Gateway Defense | Test Coverage |
|---|---|---|
| **Prompt Injection via Files** | Gateway policy engine validates every requested action deterministically regardless of instruction source. | `test_prompt_injection_enforcement_scenario` |
| **Path Traversal (`../`)** | Canonical path resolution verifying `resolved.is_relative_to(workspace)`. | `test_path_traversal_attempts_blocked` |
| **Symlink Escape** | Walks path components and checks target destinations against resolved workspace root. | `test_symlink_escape_blocked`, `test_docker_filesystem_isolation_canary` |
| **Arbitrary Host Commands** | Strict command allowlist and argument vector validation (never raw shell string or `shell=True`). | `test_disallowed_command_denied`, `test_raw_shell_string_arguments_rejected` |
| **Runaway Process / Hang** | Subprocess timeout coupled with guaranteed container kill (`docker rm -f`). | `test_executor_timeout_and_kill`, `test_docker_runaway_command_timeout_and_cleanup` |
| **Memory / CPU Exhaustion** | Docker cgroups limits (`--memory 256m`, `--cpus 1.0`, `--pids-limit 64`). | `test_build_docker_run_args_hardening` |
| **Network Exfiltration** | Docker container network disabled (`--network none`). | `test_docker_network_isolation_canary` |
| **Request Flooding / Large Payloads** | Gateway 2MB request size limit middleware and tool size caps. | `test_oversized_request_payload_rejected`, `test_read_file_size_limit` |
| **Server Crash / Restarts** | SQLite WAL mode persistence for tasks and audit events. | `test_task_state_survives_api_restart` |

### Honest Limitations
- **Single Host / Single Workspace:** AgentFence is a local reference monitor for one machine, one user, and one workspace directory, not an enterprise multi-tenant cloud sandbox.
- **Shared Kernel:** Docker containers share the host Linux/macOS kernel. AgentFence does not protect against zero-day Linux kernel privilege escalations or container escapes.
- **Parallel Host Access:** If the host process running the agent has direct terminal access outside of AgentFence, the gateway cannot enforce constraints over that bypass.

---

## Prerequisites

- **Python:** 3.12+ (standard library `tomllib` and `sqlite3` required)
- **Docker:** (Optional for unit tests; required for live container isolation tests and container execution)

---

## Setup & Installation

```bash
# 1. Clone repository and navigate to workspace
git clone https://github.com/sohaib_04/agentfence.git
cd agentfence

# 2. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies in editable mode
pip install -e ".[dev]"

# 4. (Optional) Build sandbox Docker image if running container commands
docker build -t agentfence-sandbox:0.1.0 -f Dockerfile.sandbox .
```

---

## Running Tests

Run the complete test suite with Pytest:
```bash
pytest -v
```

Run code formatting and linting checks:
```bash
ruff format --check .
ruff check .
```

*Test Results:* **62 tests** total (unit, integration, Docker container isolation, and adversarial prompt-injection scenarios). When Docker is offline, Docker-dependent tests are skipped cleanly and reported explicitly.

---

## Running the Terminal Demo

A standalone terminal demo demonstrates the three core guarantees:
1. Legitimate workspace read/write/list.
2. Adversarial denials (traversals, symlinks, disallowed commands, and prompt injection).
3. Runaway command timeout enforcement and SQLite audit trail inspection.

```bash
python demo.py
```

---

## Running the API Gateway

Start the local gateway on loopback (`127.0.0.1:8000`):
```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### API Examples

Default local development token: `agentfence-dev-token` (configurable via `AGENTFENCE_AUTH_TOKEN`).

#### 1. Liveness Check
```bash
curl -X GET http://127.0.0.1:8000/health
```
*Response:*
```json
{"status": "ok", "version": "0.1.0"}
```

#### 2. Execute a Legitimate Write Action
```bash
curl -X POST http://127.0.0.1:8000/v1/actions \
  -H "Authorization: Bearer agentfence-dev-token" \
  -H "Content-Type: application/json" \
  -d '{"tool": "write_file", "arguments": {"path": "hello.txt", "content": "Hello World"}}'
```
*Response:*
```json
{
  "task_id": "8fb87019-33ad-43ec-8b29-e0d297a7e366",
  "tool": "write_file",
  "decision": "allow",
  "reason": "allowed",
  "policy_version": "1.0.0",
  "status": "success",
  "result": {"path": "hello.txt", "bytes_written": 11},
  "error": null
}
```

#### 3. Attempt a Path Traversal Attack
```bash
curl -X POST http://127.0.0.1:8000/v1/actions \
  -H "Authorization: Bearer agentfence-dev-token" \
  -H "Content-Type: application/json" \
  -d '{"tool": "read_file", "arguments": {"path": "../../etc/passwd"}}'
```
*Response:*
```json
{
  "task_id": "426176a9-8d75-4309-90bc-937b2d5d8520",
  "tool": "read_file",
  "decision": "deny",
  "reason": "path_outside_workspace",
  "policy_version": "1.0.0",
  "status": "denied",
  "result": null,
  "error": null
}
```

#### 4. Retrieve Persisted Task State
```bash
curl -X GET http://127.0.0.1:8000/v1/tasks/8fb87019-33ad-43ec-8b29-e0d297a7e366 \
  -H "Authorization: Bearer agentfence-dev-token"
```

#### 5. Inspect Audit Log
```bash
curl -X GET "http://127.0.0.1:8000/v1/audit?limit=10" \
  -H "Authorization: Bearer agentfence-dev-token"
```

---

## Realistic Future Work

1. **Untrusted Model Planner Adapter:** Integrating an external LLM provider treated as an untrusted planner passing structured output through the gateway.
2. **Approval Flow for File Deletion:** Interactive human-in-the-loop approval confirmation for destructive tools such as `delete_file`.
3. **gVisor (`runsc`) Runtime Integration:** Evaluating gVisor container runtime sandboxing alongside standard Linux namespaces to further reduce kernel attack surface.
