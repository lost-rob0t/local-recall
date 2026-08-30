from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts" / "run-pytest"
POLICY = ROOT / "scripts" / "check-policy"
VERIFY = ROOT / "scripts" / "verify-failure-modes"
EXPECTED_FAILURE_MODES = 9


def _load_policy_module():
    from importlib.machinery import SourceFileLoader

    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        loader = SourceFileLoader("local_recall_check_policy", str(POLICY))
        spec = importlib.util.spec_from_loader("local_recall_check_policy", loader)
        assert spec is not None
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
        cache = POLICY.parent / "__pycache__"
        if cache.is_dir():
            import shutil

            shutil.rmtree(cache, ignore_errors=True)
    return module


def _run(command: list[str], *, timeout: float = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


@pytest.mark.timeout(30)
def test_zero_test_selection_fails_the_runner() -> None:
    completed = _run([str(RUNNER), "tests/security", "-k", "zzz_no_matching_test_zzz"])
    assert completed.returncode != 0


@pytest.mark.timeout(60)
def test_failure_propagation_script_injects_a_failure_into_every_mode() -> None:
    completed = _run([sys.executable, str(VERIFY)])
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert f"verified {EXPECTED_FAILURE_MODES} failure modes" in completed.stdout


def test_failure_fixtures_cover_assertion_crash_timeout_zero_selection_and_pipes() -> None:
    text = VERIFY.read_text(encoding="utf-8")
    for required in ("assertion", "crash", "timeout", "zero-tests", "zero-selection", "piped"):
        assert required in text


def test_check_policy_rejects_disabled_tests_and_false_green_constructs() -> None:
    module = _load_policy_module()
    skip_marker = "pytest.mark." + "skip"
    xfail_marker = "pytest.mark." + "xfail"
    imperative_skip = "pytest.skip" + "("
    probes = {
        "pytest skip marker": skip_marker + "(reason='x')\n",
        "pytest expected failure": "@"
        + xfail_marker
        + "\ndef test_x() -> None:\n    raise AssertionError\n",
        "imperative pytest skip": "def test_x() -> None:\n    " + imperative_skip + "no')\n",
        "ignored shell failure": "cmd || " + "true\n",
        "unconditional shell success": "\nexit " + "0\n",
        "GitHub Actions continue-on-error": "continue-on-" + "error: true\n",
        "failure-tolerant CI": "allow_" + "failure: true\n",
    }
    patterns = {**module.FALSE_GREEN_PATTERNS, **module.DISABLED_TEST_PATTERNS}
    for label, content in probes.items():
        matched = any(pattern.search(content) for pattern in patterns.values())
        if not matched:
            raise AssertionError(f"check-policy pattern set failed to detect: {label}")


def test_repository_has_no_disabled_tests_right_now() -> None:
    completed = _run([sys.executable, str(POLICY)])
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_failure_fixtures_exist_for_every_injected_mode() -> None:
    fixtures = ROOT / "tests" / "failure_fixtures"
    for required in (
        "assertion.py.txt",
        "collection.py.txt",
        "crash.py.txt",
        "signal.py.txt",
        "teardown.py.txt",
        "timeout.py.txt",
    ):
        assert (fixtures / required).is_file()
