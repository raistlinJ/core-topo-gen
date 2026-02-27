from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "flag_test_core_e2e_check.py"


def _enabled() -> bool:
    return str(os.getenv("CORETG_RUN_LIVE_FLAG_CORE_SMOKE", "")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
        "y",
    }


@pytest.mark.skipif(not _enabled(), reason="Set CORETG_RUN_LIVE_FLAG_CORE_SMOKE=1 to run live CORE smoke")
def test_live_flag_core_smoke_script() -> None:
    assert SCRIPT.exists(), f"missing smoke script: {SCRIPT}"

    env = os.environ.copy()
    env.setdefault("PYTHONUNBUFFERED", "1")
    proc = subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )
    output = (proc.stdout or "") + ("\n" if proc.stdout and proc.stderr else "") + (proc.stderr or "")
    assert proc.returncode == 0, output
