"""Layer 4 regression — wraps tools/replay_persona_baseline.py + swap_persona_test.py.

These tests are skipped unless the operator sets environment variables:
  PERSONA_REGRESSION_TARGET  -- hostname/IP of beelzebub running with Crestfield persona
  PERSONA_SWAP_TARGET        -- hostname/IP of beelzebub running with Globex persona
  PORT_MAP                   -- JSON object mapping original ports to remapped ports

Example (local docker-compose):
  PERSONA_REGRESSION_TARGET=localhost \\
  PERSONA_SWAP_TARGET=localhost \\
  PORT_MAP='{"22": 12222, "2222": 12223, "3306": 13306, "6379": 16379, \\
             "8086": 18086, "8000": 18000, "8001": 18001, "8888": 18888, \\
             "11434": 11434, "18789": 18789}' \\
  pytest bzb/tests/test_persona_regression.py -v -m regression

The workflow requires:
  1. Render Crestfield persona (`bzb persona render`), bring up beelzebub via
     tools/docker-compose.baseline.yml (mounts the rendered tree directly via
     RENDER_OUT), set PERSONA_REGRESSION_TARGET.
  2. Run test_crestfield_persona_regression.
  3. Tear down Crestfield, render Globex, point RENDER_OUT at the new tree,
     bring up beelzebub, set PERSONA_SWAP_TARGET.
  4. Run test_persona_swap_no_bleed.
  5. Tear down Globex.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
BASELINE = REPO / "tests" / "persona-baseline-crestfield.jsonl"


@pytest.mark.regression
def test_crestfield_persona_regression():
    """Replay all 28 probes against Crestfield-mounted beelzebub; diff against baseline.

    Pass criterion: every probe matches its baseline within tolerance
    (exact byte-match after timestamp/UUID normalization for deterministic
    probes; bounded length + no self-reference for LLM-variable probes).
    """
    target = os.environ.get("PERSONA_REGRESSION_TARGET")
    if not target:
        pytest.skip(
            "set PERSONA_REGRESSION_TARGET=<host> to run regression "
            "(requires beelzebub running with Crestfield persona)"
        )
    port_map = os.environ.get("PORT_MAP", "{}")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.replay_persona_baseline",
            "--target", target,
            "--baseline", str(BASELINE),
            "--persona-strings", "crestfield,Crestfield,crestfielddata.io",
            "--port-map", port_map,
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO),
    )
    if result.returncode != 0:
        pytest.fail(
            f"Crestfield regression failures:\n{result.stdout}\n{result.stderr}"
        )


@pytest.mark.regression
def test_persona_swap_no_bleed():
    """Swap test: with a non-Crestfield persona mounted, no Crestfield strings appear.

    Pass criterion: zero occurrences of banned Crestfield/framework strings
    in any of the 28 probe response bodies.
    """
    target = os.environ.get("PERSONA_SWAP_TARGET")
    if not target:
        pytest.skip(
            "set PERSONA_SWAP_TARGET=<host> to run swap test "
            "(requires beelzebub running with Globex or other non-Crestfield persona)"
        )
    port_map = os.environ.get("PORT_MAP", "{}")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.swap_persona_test",
            "--target", target,
            "--port-map", port_map,
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO),
    )
    if result.returncode != 0:
        pytest.fail(
            f"Swap-test failures (persona bleed detected):\n{result.stdout}\n{result.stderr}"
        )
