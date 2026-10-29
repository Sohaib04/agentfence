# Security Policy

## Reporting a Vulnerability

AgentFence is a security-focused project designed as a deterministic local reference monitor for AI agents. If you discover a vulnerability, policy bypass, or sandbox escape, we appreciate your help in disclosing it responsibly.

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report security vulnerabilities by emailing:
**sohaibb876@gmail.com**

Please include in your report:
- A description of the vulnerability, bug, or security bypass.
- Steps to reproduce or a minimal proof-of-concept (PoC) script.
- The environment configuration (OS, Docker version, Python version, runtime e.g. `runc` vs `runsc`).
- Potential impact on host systems or workspaces.

We will acknowledge receipt of your report within 48 hours and work with you on a resolution before any public disclosure.

---

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

---

## Security Model & Threat Boundaries

AgentFence operates under the **Untrusted Model Principle**:
1. **The Model is Untrusted:** Model proposals (tool calls, file paths, shell commands) are treated as untrusted input.
2. **The Policy Engine is Trusted Code:** Authorization decisions are deterministic and fail-closed.
3. **The Execution Environment Enforces Isolation:** Command execution runs inside an unprivileged Docker/gVisor container with dropped capabilities and no network access.
4. **Local Gateway Boundary:** The API binds to localhost loopback (`127.0.0.1`) with token authentication and request size bounding.

For full architectural details, consult the [Threat Model in the README](README.md#threat-model).

