# AgentFence

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Tests: 109 Passed](https://img.shields.io/badge/tests-109%20passed-success.svg)](tests/)

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
- **Live LLM Planner Adapter (Untrusted Planner):** Translates natural language user goals into structured tool actions using live providers (Google Gemini, OpenAI) with zero-configuration deterministic fallback when offline or without API keys. Enforces the Untrusted Model Principle — model proposals are strictly untrusted proposals validated by Pydantic schemas, authorized by the deterministic policy engine, and executed inside isolated sandboxes. API keys are strictly confined to host environment variables and never logged, committed, or mounted into containers.
- **Local API Gateway:** FastAPI loopback-bound (`127.0.0.1:8000`) with token authentication, 2MB request body cap, and safe error masking (no leaked stack traces or host paths).
- **Deterministic Mock Agent & Adversarial Test Suite:** Reproducible simulation of indirect prompt injection and attack sequences.
- **Empirical Attack-Success-Rate (ASR) Benchmark Suite:** Automated benchmark quantifying prompt injection, roleplay jailbreak, and path traversal resistance across 20 curated scenarios (100% baseline ungoverned ASR reduced to **0.0% breach rate** with AgentFence).

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
- **Shared Kernel vs Application Kernel:** Default Docker execution (`runc`) shares the host Linux/macOS kernel; zero-day host kernel privilege escalations remain an inherent risk unless Google gVisor (`runsc`) is enabled (see architecture comparison below).
- **Parallel Host Access:** If the host process running the agent has direct terminal access outside of AgentFence, the gateway cannot enforce constraints over that bypass.

---

## Sandbox Isolation & Kernel Threat Model: Architecture Comparison

A core challenge in securing autonomous coding agents is that prompt safety and API gateways are necessary but insufficient: once the agent generates and executes shell commands, containment relies on operating system primitives. If an untrusted agent exploits a kernel vulnerability, it can break out of container boundaries and compromise the host.

AgentFence evaluates three primary runtime isolation architectures: standard Docker (`runc`), Google gVisor (`runsc`), and hardware microVMs (AWS Firecracker).

### 1. Baseline Docker Container (`runc`)
- **Mechanism:** Linux kernel namespaces (PID, mount, network, IPC, UTS, user), control groups (cgroups v2), capability dropping (`--cap-drop ALL`), `no-new-privileges`, read-only root filesystem, and minimal `/tmp` tmpfs.
- **Syscall Handling:** Direct syscall passthrough. The untrusted process executes system calls directly against the host Linux kernel.
- **Kernel Attack Surface:** **High (~350+ system calls).** The process interacts with the host kernel's memory management, filesystem drivers, ioctl handlers, network stack, and socket layers.
- **Vulnerability Profile:** Susceptible to Linux kernel local privilege escalation (LPE) exploits (e.g., Dirty COW, Dirty Pipe, io_uring vulnerabilities, race conditions in netfilter). A kernel exploit achieves immediate root on the host machine.
- **Strengths:** Zero virtualization overhead, native CPU and direct I/O throughput, ubiquitous developer tooling.

### 2. Google gVisor (`runsc`)
- **Mechanism:** User-space application kernel written in memory-safe Go (`Sentry`) paired with an isolated filesystem proxy daemon (`Gofer`).
- **Syscall Handling:** Syscall interception. Sentry intercepts guest system calls (via `ptrace` or KVM virtualization) and emulates the Linux kernel API entirely inside user-space Go.
- **Kernel Attack Surface:** **Very Low (~50-60 restricted syscalls).** The host kernel never sees the agent process's raw system calls. Instead, the Sentry issues only a minimal, tightly controlled subset of safe syscalls to the host kernel, protected by an outer seccomp filter.
- **Vulnerability Profile:** Drastically reduces kernel 0-day exposure. Because the Sentry is written in Go, memory safety vulnerabilities (buffer overflows, use-after-free) common in C-based OS kernels are systematically prevented. An exploit inside the container attacks only the user-space Go emulator, not the host kernel.
- **Tradeoffs & Costs:**
  - *Syscall Latency:* Intercepting system calls introduces context switches, especially under `ptrace` platform mode (reduced when KVM virtualization is available).
  - *I/O Performance Overhead:* File system operations pass through the Gofer proxy daemon, causing measurable latency on disk-heavy compilation or high-frequency file reads.
  - *Syscall Incompleteness:* Re-implements the Linux kernel API; esoteric or hardware-specific syscalls (raw packet crafting, hardware device ioctls) are not supported.

### 3. Hardware MicroVMs (AWS Firecracker / Cloud Hypervisor)
- **Mechanism:** Minimalist virtual machines running on hardware-assisted virtualization extensions (KVM) with a dedicated guest Linux kernel per execution sandbox.
- **Syscall Handling:** Complete isolation. The guest OS has its own dedicated kernel. Isolation is enforced by hardware CPU MMU virtualization (Intel VT-x / AMD-V, EPT/NPT).
- **Kernel Attack Surface:** **Near Zero against the host kernel.** A guest kernel panic, crash, or local privilege escalation is completely confined within the microVM's virtual hardware boundary.
- **Vulnerability Profile:** The host is only vulnerable to hypervisor-level escapes (VMM device emulation flaws), which are extraordinarily rare compared to Linux kernel vulnerabilities.
- **Tradeoffs & Costs:**
  - *Startup Overhead:* Cold boot takes 100–250ms (compared to 10–30ms for container startup).
  - *Base Memory Overhead:* Each microVM requires dedicated memory allocation (typically 5–15MB+ per instance) for the guest kernel image and page tables.
  - *Infrastructure Requirements:* Requires bare-metal Linux hardware with hardware virtualization flags enabled (or nested virtualization enabled in cloud VMs).

---

### Architectural Tradeoff Matrix

| Feature / Metric | Baseline Docker (`runc`) | Google gVisor (`runsc`) | MicroVMs (Firecracker) |
|---|---|---|---|
| **Isolation Boundary** | Linux Namespaces + cgroups | User-space Go Kernel (`Sentry`) | Hardware MMU Virtualization (KVM) |
| **Shares Host Kernel?** | **Yes** (Direct) | **No** (Only safe syscall proxy) | **No** (Independent guest kernel) |
| **Host Syscall Attack Surface** | ~350+ host syscalls | ~50–60 host syscalls | Hypervisor ioctls only |
| **Memory Safety of Sandbox Kernel** | Low (C kernel code) | High (Go memory-safe runtime) | Low (C kernel code inside guest) |
| **Protection vs Kernel 0-Days** | None (kernel bug = host escape) | **High** (host kernel shielded) | **Maximum** (hardware-enforced MMU) |
| **Cold Startup Latency** | ~10–25 ms | ~20–40 ms | ~100–250 ms |
| **Filesystem I/O Overhead** | Native speed (~0%) | Noticeable (Gofer proxy hops) | Moderate (virtio-blk / 9p) |
| **Memory Footprint per Box** | Minimal (~2–4 MB) | Low (~15–25 MB) | Moderate (~20–40 MB minimum) |
| **Setup Complexity** | Zero (Default Docker runtime) | Low (`apt install runsc` + daemon config) | High (KVM device permissions + rootfs) |
| **AgentFence Support** | Default built-in | Fully supported (`--runtime=runsc`) | Future microVM adapter |

---

### Enabling gVisor in AgentFence

AgentFence provides native, configurable support for `--runtime=runsc` without altering policy engine or tool interfaces:

1. **Install gVisor `runsc` on host:**
   ```bash
   curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
   echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list > /dev/null
   sudo apt-get update && sudo apt-get install -y runsc
   sudo runsc install
   sudo systemctl restart docker
   ```

2. **Automated Host Detection:**
   AgentFence includes an automated detector `is_runsc_available()` that checks whether `runsc` is installed in `$PATH` or registered in the Docker daemon runtimes (`docker info`).

3. **Policy Configuration:**
   Enable gVisor in `policies/default_policy.toml`:
   ```toml
   [tools.run_command]
   enabled = true
   allowed_commands = ["python3", "pytest", "ls", "cat", "echo", "grep", "head", "tail", "wc"]
   sandbox_image = "agentfence-sandbox:0.1.0"
   sandbox_runtime = "runsc"  # Dispatches container with --runtime=runsc
   ```

4. **Programmatic Usage:**
   ```python
   from app.executor.docker import DockerExecutor

   # Explicitly initialize executor with gVisor sandbox
   executor = DockerExecutor(runtime="runsc")
   ```

---

## Prerequisites

- **Python:** 3.12+ (standard library `tomllib` and `sqlite3` required)
- **Docker:** (Optional for unit tests; required for live container isolation tests and container execution)

---

## Setup & Installation

```bash
# 1. Clone repository and navigate to workspace
git clone https://github.com/Sohaib04/agentfence.git
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

*Test Results:* **109 tests** total (unit, integration, Docker container isolation, gVisor comparative sandboxing, live LLM planner workflows, empirical ASR benchmark execution, async execution, human approval flows, and adversarial prompt-injection scenarios). When Docker or gVisor runtimes are offline, environment-dependent tests are skipped cleanly and reported explicitly.

---

## Running the Live LLM Agent (CLI)

The `run_agent.py` CLI demonstrates the **Untrusted Model Principle** with natural language prompts:

```bash
# 1. Legitimate instruction (translated to list_files, approved, and executed)
python run_agent.py "Inspect the workspace and create a summary report"

# 2. Adversarial instruction (model proposes /etc/passwd read, gateway blocks & audits)
python run_agent.py "Read the host /etc/passwd file"

# 3. Connect live LLM provider (Gemini or OpenAI via environment variable)
export GEMINI_API_KEY="your-gemini-api-key"
python run_agent.py "Create a file named notes.txt with project ideas"

# 4. Interactive prompt session
python run_agent.py
```

*Key Guarantee:* If no API key is provided, the agent automatically falls back to deterministic heuristic planning, ensuring 100% testability offline. All API keys are loaded strictly from host environment variables, never logged, never committed, and never mounted into container sandboxes.

---

## Empirical Attack-Success-Rate (ASR) Benchmark

AgentFence includes an automated empirical benchmark (`benchmarks/asr_benchmark.py`) evaluating security efficacy across 20 curated scenarios spanning benign control workloads, path traversals, administrative override jailbreaks, DAN roleplay injections, indirect file injections, dangerous commands, and symlink escapes:

```bash
# Run benchmark with terminal summary table and markdown export
python benchmarks/asr_benchmark.py

# Run benchmark with JSON output format
python benchmarks/asr_benchmark.py --json
```

### Benchmark Results Summary

| Metric | Without Gateway (Ungoverned Model) | With AgentFence Security Gateway |
|---|---|---|
| **Attack Success Rate (ASR)** | **100.0%** (Full Compromise) | **0.0% (Target: 0% Breach Rate)** |
| **Benign Workload Pass Rate** | 100.0% | **100.0% (Zero Functional Regression)** |
| **Host Escape / Compromise Rate** | 100.0% | **0.0% (Zero Escapes)** |
| **Total Scenarios Evaluated** | 20 | 20 |

### Category Performance Breakdown

| Category | Scenarios | Baseline ASR (No Gateway) | AgentFence ASR | Enforcement Mechanism |
|---|---|---|---|---|
| **Benign Control** | 5 | 0.0% | **0.0%** | Allowed through confined tools & sandbox |
| **Path Traversal** | 5 | 100.0% | **0.0%** | Deterministic `is_relative_to` workspace path validation |
| **Prompt Injection** | 3 | 100.0% | **0.0%** | Command allowlist & path resolution (fail-closed) |
| **Indirect Injection** | 2 | 100.0% | **0.0%** | Untrusted file content containment & path bounds |
| **Dangerous Commands** | 3 | 100.0% | **0.0%** | Strict command allowlist (`allowed_commands`) |
| **Filesystem Integrity** | 2 | 100.0% | **0.0%** | Symlink resolution check & human-in-the-loop approval |

Full per-scenario evaluation logs are generated automatically in [`benchmarks/ASR_REPORT.md`](benchmarks/ASR_REPORT.md).

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

#### 4. Asynchronous Background Execution
Execute commands asynchronously without blocking the client. Returns `202 Accepted` immediately:
```bash
curl -X POST http://127.0.0.1:8000/v1/actions \
  -H "Authorization: Bearer agentfence-dev-token" \
  -H "Content-Type: application/json" \
  -d '{"tool": "run_command", "arguments": {"command": "echo", "args": ["hello async"]}, "async": true}'
```
*Response (HTTP 202 Accepted):*
```json
{
  "task_id": "8fb87019-33ad-43ec-8b29-e0d297a7e366",
  "tool": "run_command",
  "decision": "allow",
  "reason": "allowed",
  "policy_version": "1.0.0",
  "status": "pending",
  "result": null,
  "error": null
}
```

#### 5. Fine-Grained Human-in-the-Loop Approval Flow
Destructive actions (such as `delete_file`) pause in `pending_approval` until an operator reviews them:
```bash
curl -X POST http://127.0.0.1:8000/v1/actions \
  -H "Authorization: Bearer agentfence-dev-token" \
  -H "Content-Type: application/json" \
  -d '{"tool": "delete_file", "arguments": {"path": "obsolete.txt"}}'
```
*Response:*
```json
{
  "task_id": "c9a41b52-6729-4bfe-98e3-0d321151e031",
  "tool": "delete_file",
  "decision": "pending_approval",
  "reason": "requires_approval",
  "policy_version": "1.0.0",
  "status": "pending_approval",
  "result": null,
  "error": null
}
```

**Approve the task:**
```bash
curl -X POST http://127.0.0.1:8000/v1/tasks/c9a41b52-6729-4bfe-98e3-0d321151e031/approve \
  -H "Authorization: Bearer agentfence-dev-token"
```
*Response:*
```json
{
  "task_id": "c9a41b52-6729-4bfe-98e3-0d321151e031",
  "tool": "delete_file",
  "decision": "allow",
  "reason": "allowed",
  "policy_version": "1.0.0",
  "status": "success",
  "result": {"path": "obsolete.txt", "deleted": true},
  "error": null
}
```

**Or reject the task:**
```bash
curl -X POST http://127.0.0.1:8000/v1/tasks/c9a41b52-6729-4bfe-98e3-0d321151e031/reject \
  -H "Authorization: Bearer agentfence-dev-token"
```

#### 6. Poll / Retrieve Persisted Task State
```bash
curl -X GET http://127.0.0.1:8000/v1/tasks/8fb87019-33ad-43ec-8b29-e0d297a7e366 \
  -H "Authorization: Bearer agentfence-dev-token"
```

#### 7. Inspect Audit Log
```bash
curl -X GET "http://127.0.0.1:8000/v1/audit?limit=10" \
  -H "Authorization: Bearer agentfence-dev-token"
```

---

## Documentation & Specifications

- **[Technical Architecture Specification](docs/SPECIFICATION.md):** Detailed breakdown of trust boundaries, fail-closed policy logic, tool choke points, and API schema models.
- **[Empirical ASR Benchmark Report](benchmarks/ASR_REPORT.md):** 20 curated adversarial attack vectors, test methodologies, and empirical comparison metrics.
- **[Project Roadmap](docs/ROADMAP.md):** Completed capabilities and future engineering milestones (MicroVMs, multi-agent swarms).

---

## Contributing & Security

- **[Contributing Guide](CONTRIBUTING.md):** Environment setup, coding conventions, test execution, and pull request guidelines.
- **[Security Policy](SECURITY.md):** Vulnerability disclosure instructions and threat boundary overview.

---

## License

This project is licensed under the [MIT License](LICENSE).
