# Contributing to AgentFence

Thank you for your interest in contributing to AgentFence. We welcome contributions that improve agent safety, sandboxing security, and policy enforcement.

---

## Code of Conduct

We are committed to providing a welcoming, constructive, and harassment-free environment for everyone. Please be respectful and professional in all interactions.

---

## Development Setup

### 1. Prerequisites
- **Python:** 3.12 or newer.
- **Docker:** (Optional for unit tests; required for container execution and sandbox tests).
- **Git**

### 2. Fork and Clone
```bash
git clone https://github.com/<your-username>/agentfence.git
cd agentfence
```

### 3. Virtual Environment Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"
```

### 4. Build Sandbox Image (Optional for container tests)
```bash
docker build -t agentfence-sandbox:0.1.0 -f Dockerfile.sandbox .
```

---

## Quality Standards

Before submitting a Pull Request, ensure all checks pass:

### 1. Run Unit and Integration Tests
```bash
pytest -v
```
All tests should pass. Container-dependent tests will skip automatically if Docker is unavailable.

### 2. Format and Lint Code
We enforce strict formatting and linting via Ruff:
```bash
# Check formatting
ruff format --check .

# Automatically apply formatting
ruff format .

# Check lint rules
ruff check .
```

---

## Pull Request Guidelines

1. **Keep PRs Focused:** Submit small, targeted PRs addressing a single feature or bug fix.
2. **Include Tests:** Any new policy rule, tool, or endpoint must include unit and integration tests.
3. **Preserve Determinism:** Never rely on an LLM to evaluate safety policies. Policy decisions must remain deterministic and fail-closed.
4. **Never Weaken Sandboxing:** Do not weaken container boundaries (e.g. adding root privileges, mounting docker socket, enabling network without justification) to pass tests.
