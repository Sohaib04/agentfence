# AgentFence Technical Specification

> **Deterministic Reference Monitor & Sandboxed Execution Gateway for AI Agents**

---

## 1. Overview & Core Philosophy

AgentFence acts as a local security gateway mediating an autonomous AI agent's access to files and operating system commands. The agent formulates and proposes structured tool actions, a deterministic policy engine evaluates each proposal against an explicit security policy, approved actions run through confined tools or an isolated container sandbox, and all actions and outcomes are recorded in an audit store.

**Core Principle:** *The agent proposes, our code decides, the operating system enforces.* A prompt instructing a model to behave is not a security control, and an LLM judging another LLM does not provide deterministic security guarantees.

---

## 2. Trust Boundaries

1. **The Model is Untrusted:** The model (LLM or agentic script) is treated as an untrusted actor. It may hallucinate, fall victim to indirect prompt injection in repository files, or actively propose malicious operations. Model proposals are untrusted data requiring schema validation and deterministic policy evaluation.
2. **The Policy Engine is Trusted Application Code:** The authorization engine is completely deterministic, tested independently of web frameworks or LLMs, and fails closed on any unhandled exception or parsing failure.
3. **The Execution Environment Enforces Isolation Independently:** Policy rules alone cannot stop a runaway or memory-intensive program once launched; container resource limits, Linux namespaces, and capability dropping enforce containment at the OS kernel boundary.
4. **Single Choke-Point Tool Dispatcher:** Tools cannot be invoked through parallel code paths. Every tool invocation must flow through the central dispatcher following policy evaluation.

---

## 3. Technology Stack

| Component | Technology | Rationale |
|---|---|---|
| Language | Python 3.12+ | Native `tomllib`, modern typing, pattern matching |
| Gateway Framework | FastAPI + Uvicorn | High-performance asynchronous API, Pydantic schemas |
| Schemas | Pydantic v2 | Strict JSON schema validation and serialization |
| Sandbox Isolation | Docker (`runc`) / gVisor (`runsc`) | Strong kernel namespace, cgroup, and syscall containment |
| Persistence & Audit | SQLite (stdlib `sqlite3`) | Zero-dependency, crash-resilient WAL mode persistence |
| Testing & Linting | Pytest + HTTPX + Ruff | Fast, reproducible test suite and lint enforcement |

---

## 4. Architecture & Request Flow

```
Agent Client
     │  (Structured JSON Action Proposal)
     ▼
FastAPI Gateway (Loopback 127.0.0.1, Token Auth, 2MB Request Cap)
     │
     ▼
Policy Engine (Deterministic authorization, fail-closed, no LLMs)
     │
     ├──[ DENIED ]────────► Record Denial in SQLite Audit Store ──► Return Status "denied"
     │
     ├──[ PENDING APPROVAL ]► Record Pending in SQLite Store ──► Await Human Decision
     │
     └──[ ALLOWED ]───────► Tool Dispatcher (Single Choke Point)
                                 │
                   ┌─────────────┴─────────────┐
                   ▼                           ▼
           Confined File Tools        Restricted Docker Sandbox
           (Path containment,         (--network none, --read-only root,
            symlink escape check)      --cap-drop ALL, cgroup limits)
                   │                           │
                   └─────────────┬─────────────┘
                                 │
                                 ▼
                        SQLite Audit Store
                        (Immutable log, redacted secrets & file bodies)
```

---

## 5. Tool Capabilities & Policy Matrix

| Tool | Capability | Default Policy Behavior |
|---|---|---|
| `list_files` | List workspace contents | Allowed within resolved workspace bounds |
| `read_file` | Read workspace file contents | Allowed within workspace bounds (max 1MB) |
| `write_file` | Create or modify workspace file | Allowed within workspace bounds (max 1MB) |
| `delete_file` | Delete workspace file | Pauses for human-in-the-loop approval |
| `run_command` | Execute shell command in sandbox | Allowed only for command allowlist in isolated container |
| `network_request` | Outbound network communication | Denied by default (container `--network none`) |
| `open_application` | Launch host graphical applications | Disabled / Denied |

---

## 6. API Interface Contracts

### 1. `POST /v1/actions`
Propose a structured tool action for authorization and execution.

**Request:**
```json
{
  "tool": "read_file",
  "arguments": {
    "path": "src/main.py"
  },
  "async": false
}
```

**Response (Allowed & Executed):**
```json
{
  "task_id": "8fb87019-33ad-43ec-8b29-e0d297a7e366",
  "tool": "read_file",
  "decision": "allow",
  "reason": "allowed",
  "policy_version": "1.0.0",
  "status": "success",
  "result": {"content": "...", "size_bytes": 1024},
  "error": null
}
```

**Response (Denied):**
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

### 2. `POST /v1/tasks/{task_id}/approve` & `reject`
Explicit human review for high-impact actions (e.g., file deletion).

### 3. `GET /v1/tasks/{task_id}`
Retrieve task state, lifecycle timestamps, and recorded outcome.

### 4. `GET /v1/audit`
Paginated inspection of recorded audit records with automatic credential redaction.

### 5. `GET /health`
Liveness check returning service status without invoking sandbox containers.

