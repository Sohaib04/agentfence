# AgentFence Roadmap

This document outlines completed milestones and future engineering directions for AgentFence.

---

## Completed Milestones

### Milestone 1: Deterministic Policy Engine & Confined File Tools
- Fail-closed deterministic authorization engine based on TOML security policies.
- Canonical path resolution and containment verification blocking `../` directory traversals, root escapes, and symlink targets.
- Single choke-point tool dispatcher preventing bypass of policy enforcement.
- Bounded file tools (`list_files`, `read_file`, `write_file`) with 1MB size caps.
- Loopback-bound (`127.0.0.1`) FastAPI gateway with token authentication and 2MB request body caps.

### Milestone 2: Restricted Container Execution
- Docker-based sandboxed command execution (`run_command`) with pinned base image.
- Container hardening: `--network none`, `--read-only` rootfs, `--cap-drop ALL`, `no-new-privileges`, unprivileged UID (`10001:10001`).
- Resource boundaries: memory caps (256MB), CPU limits (1.0), and process limits (`pids-limit 64`).
- Wall-clock timeout enforcement with guaranteed container termination (`docker rm -f`).
- Bounded stdout/stderr capture with safe truncation markers.

### Milestone 3: Crash-Resilient Audit & Task Persistence
- SQLite persistence using standard library `sqlite3` in WAL mode.
- Full task lifecycle logging surviving gateway cold restarts.
- Automatic redaction of credentials (`token`, `auth`, `password`, `key`, `secret`) in audit trails.
- Suppression of full file bodies to protect data privacy.

### Milestone 4: Live LLM Planner & Untrusted Model Integration
- Adapter translating natural language prompts to structured tool actions (Gemini, OpenAI).
- Deterministic heuristic fallback for offline, zero-configuration testing.
- Secure environment variable isolation (API keys are never logged, committed, or mounted into sandboxes).

### Milestone 5: Empirical Attack-Success-Rate (ASR) Benchmark
- Automated benchmark framework evaluating 20 curated adversarial scenarios.
- Quantified 0.0% breach rate with AgentFence vs 100.0% baseline compromise without the gateway.
- Comprehensive scenario reporting exported to [`benchmarks/ASR_REPORT.md`](../benchmarks/ASR_REPORT.md).

### Milestone 6: Asynchronous Execution & Human-in-the-Loop Approvals
- Asynchronous non-blocking task submission returning `202 Accepted` and a unique `task_id`.
- Fine-grained operator review for sensitive operations (`delete_file`) via `/v1/tasks/{task_id}/approve`.
- Comparative sandboxing support for Google gVisor (`runsc`).

---

## Future Directions

### 1. Hardware MicroVM Isolation Adapter
- Native backend for AWS Firecracker or Cloud Hypervisor.
- Hardware-assisted MMU virtualization (KVM) providing a dedicated guest Linux kernel per execution sandbox.

### 2. Multi-Agent Swarm Governance
- Distributed reference monitors mediating shared workspace state across collaborative agent swarms.
- Concurrent file locking and conflict resolution policies.

### 3. Granular Network Sandboxing
- Policy-governed egress proxy allowing domain-allowlisted outbound HTTP requests with TLS inspection and secret-exfiltration detection.

