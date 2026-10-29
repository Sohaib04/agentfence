"""Automated tests verifying the Empirical Attack-Success-Rate (ASR) Benchmark suite."""

import json
import subprocess
import sys
from pathlib import Path

from benchmarks.asr_benchmark import (
    ASRBenchmarkRunner,
    generate_markdown_report,
    get_benchmark_dataset,
)


def test_benchmark_dataset_integrity():
    scenarios = get_benchmark_dataset()
    assert len(scenarios) >= 15

    ids = set()
    for sc in scenarios:
        assert sc.id not in ids, f"Duplicate scenario ID: {sc.id}"
        ids.add(sc.id)
        assert sc.name
        assert sc.category
        assert sc.prompt
        assert sc.expected_policy_decision in ["allow", "deny", "pending_approval"]
        assert sc.expected_reason

    benign = [s for s in scenarios if not s.is_adversarial]
    adversarial = [s for s in scenarios if s.is_adversarial]

    assert len(benign) >= 3
    assert len(adversarial) >= 10


def test_asr_benchmark_deterministic_execution():
    runner = ASRBenchmarkRunner(provider="mock")
    report = runner.run_benchmark()

    # Core Guarantees:
    # 1. 100% benign workloads preserved and allowed
    assert report.benign_pass_rate == 100.0
    assert report.benign_allowed == report.benign_count

    # 2. Without gateway: high vulnerability rate (100% of attacks breach)
    assert report.without_gateway_asr == 100.0
    assert report.without_gateway_breaches == report.adversarial_count

    # 3. With AgentFence gateway: exactly 0.0% breach rate (Zero host escapes)
    assert report.with_gateway_asr == 0.0
    assert report.with_gateway_breaches == 0
    assert report.host_escape_rate == 0.0

    # 4. Invariance check across each scenario
    for ev in report.evaluations:
        sc = ev.scenario
        assert ev.gateway_decision == sc.expected_policy_decision, (
            f"Scenario {sc.id} ({sc.name}) expected decision '{sc.expected_policy_decision}', "
            f"got '{ev.gateway_decision}'"
        )
        assert ev.gateway_reason == sc.expected_reason, (
            f"Scenario {sc.id} ({sc.name}) expected reason '{sc.expected_reason}', "
            f"got '{ev.gateway_reason}'"
        )
        if sc.is_adversarial:
            assert ev.with_gateway_breach is False


def test_asr_benchmark_markdown_generation():
    runner = ASRBenchmarkRunner(provider="mock")
    report = runner.run_benchmark()
    md = generate_markdown_report(report)

    assert "## Empirical Attack-Success-Rate (ASR) Benchmark Report" in md
    assert "0.0% (Target: 0% Breach Rate)" in md
    assert "100.0% (100% Preservation)" in md
    assert "0.0% (Zero Escapes)" in md
    assert "| `BENIGN-01` |" in md
    assert "| `TRAV-01` |" in md
    assert "| `JAIL-01` |" in md


def test_asr_benchmark_cli_json_mode():
    script_path = Path(__file__).resolve().parent.parent.parent / "benchmarks" / "asr_benchmark.py"
    proc = subprocess.run(
        [sys.executable, str(script_path), "--json", "--provider", "mock"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
    )

    assert proc.returncode == 0, f"Benchmark script failed: {proc.stderr}"
    data = json.loads(proc.stdout)

    assert data["total_scenarios"] == 20
    assert data["benign_pass_rate"] == 100.0
    assert data["without_gateway_asr"] == 100.0
    assert data["with_gateway_asr"] == 0.0
    assert data["host_escape_rate"] == 0.0
