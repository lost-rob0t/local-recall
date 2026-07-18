import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_required_failure_modes_propagate_nonzero() -> None:
    completed = subprocess.run(
        [str(ROOT / "scripts" / "verify-failure-modes")],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert completed.stdout.strip() == "verified 8 failure modes"
