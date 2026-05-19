"""Smoke tests for lure_lint.py — R11 MCP version coherence.

Run with:
    cd ~/projects/beelzebub
    python3 -m pytest tools/test_lure_lint.py -v
or directly:
    python3 tools/test_lure_lint.py
"""
import subprocess
import sys
import tempfile
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LURE_LINT = os.path.join(REPO_ROOT, "tools", "lure_lint.py")


def _run_lint(yaml_text: str, extra_args: list[str] | None = None) -> subprocess.CompletedProcess:
    """Write yaml_text to a temp file and run lure_lint.py on it."""
    extra_args = extra_args or []
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(yaml_text)
        tmp = f.name
    try:
        return subprocess.run(
            [sys.executable, LURE_LINT, tmp] + extra_args,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
    finally:
        os.unlink(tmp)


# ---------------------------------------------------------------------------
# R11 — per-command header/body mismatch
# ---------------------------------------------------------------------------

_MISMATCH_YAML = """\
apiVersion: v1
protocol: http
address: ":8001"
commands:
  - regex: "^/mcp$"
    headers:
      - "Content-Type: application/json"
      - "X-MCP-Version: 2025-06-18"
    handler: '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26"}}'
    statusCode: 200
  - regex: "^.*$"
    handler: '{"error":"not found"}'
    statusCode: 404
"""

_COHERENT_YAML = """\
apiVersion: v1
protocol: http
address: ":8001"
commands:
  - regex: "^/mcp$"
    headers:
      - "Content-Type: application/json"
      - "X-MCP-Version: 2025-06-18"
    handler: '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}'
    statusCode: 200
  - regex: "^.*$"
    handler: '{"error":"not found"}'
    statusCode: 404
"""

_MULTI_VERSION_YAML = """\
apiVersion: v1
protocol: http
address: ":8001"
commands:
  - regex: "^/mcp$"
    handler: '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}'
    statusCode: 200
  - regex: "^/mcp/legacy$"
    handler: '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26"}}'
    statusCode: 200
  - regex: "^.*$"
    handler: '{"error":"not found"}'
    statusCode: 404
"""


def test_R11_catches_header_body_mismatch():
    """Crafted YAML with mismatched X-MCP-Version + protocolVersion must fire R11 CRITICAL."""
    result = _run_lint(_MISMATCH_YAML)
    assert "R11" in result.stdout, (
        f"R11 didn't fire on header/body mismatch.\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "CRITICAL" in result.stdout, (
        f"R11 mismatch should be CRITICAL.\nstdout: {result.stdout}"
    )
    assert result.returncode == 1, (
        f"lure_lint should exit 1 on CRITICAL R11 violation, got {result.returncode}"
    )


def test_R11_coherent_handler_is_clean():
    """Matching X-MCP-Version header and protocolVersion body must NOT fire R11."""
    result = _run_lint(_COHERENT_YAML)
    assert "R11" not in result.stdout, (
        f"R11 falsely fired on coherent handler.\nstdout: {result.stdout}"
    )


def test_R11_multi_version_file_fires_warn():
    """File with two distinct protocolVersion values across handlers must fire R11."""
    result = _run_lint(_MULTI_VERSION_YAML)
    assert "R11" in result.stdout, (
        f"R11 file-wide check didn't fire on multi-version file.\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )


if __name__ == "__main__":
    tests = [
        test_R11_catches_header_body_mismatch,
        test_R11_coherent_handler_is_clean,
        test_R11_multi_version_file_fires_warn,
    ]
    failures = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
        except AssertionError as e:
            print(f"  FAIL  {t.__name__}: {e}")
            failures += 1
    if failures:
        print(f"\n{failures}/{len(tests)} tests FAILED")
        sys.exit(1)
    else:
        print(f"\n{len(tests)}/{len(tests)} tests passed")
        sys.exit(0)
