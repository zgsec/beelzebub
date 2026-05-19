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



# ---------------------------------------------------------------------------
# R12 — frozen ISO timestamps in handler bodies
# ---------------------------------------------------------------------------

_R12_FROZEN_YAML = """\
apiVersion: v1
protocol: http
address: ":1234"
commands:
  - regex: "^/agents$"
    headers:
      - "Content-Type: application/json"
    handler: '{"agents":[{"id":"a1","created":"2026-01-15T08:30:00Z"}]}'
    statusCode: 200
  - regex: "^.*$"
    handler: '{"error":"not found"}'
    statusCode: 404
"""

_R12_TEMPLATE_YAML = """\
apiVersion: v1
protocol: http
address: ":1234"
commands:
  - regex: "^/agents$"
    handler: '{"agents":[{"id":"a1","created":"${time.ago.120d}"}]}'
    statusCode: 200
  - regex: "^.*$"
    handler: '{"error":"not found"}'
    statusCode: 404
"""

_R12_DOC_YAML = """\
apiVersion: v1
protocol: http
address: ":1234"
description: "Lure deployed 2026-03-05T18:30:00Z to capture..."
commands:
  - regex: "^/$"
    # As of 2026-04-15T08:30:00Z — last seen
    handler: '{"ok":true}'
    statusCode: 200
  - regex: "^.*$"
    handler: '{"error":"not found"}'
    statusCode: 404
"""


def test_R12_catches_frozen_timestamp_in_handler():
    """A literal ISO timestamp in a handler body must fire R12 WARN."""
    result = _run_lint(_R12_FROZEN_YAML)
    assert "R12" in result.stdout, (
        f"R12 didn't fire on frozen timestamp.\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "2026-01-15" in result.stdout, (
        f"timestamp value should appear in R12 output.\nstdout: {result.stdout}"
    )
    assert "WARN" in result.stdout, (
        f"R12 should be WARN severity.\nstdout: {result.stdout}"
    )


def test_R12_allows_time_ago_template():
    """${time.ago.120d} replacement must NOT fire R12."""
    result = _run_lint(_R12_TEMPLATE_YAML)
    assert "R12" not in result.stdout, (
        f"R12 false positive on ${'{time.ago.120d}'} template.\nstdout: {result.stdout}"
    )


def test_R12_skips_descriptions_and_comments():
    """Documentation fields and YAML comments must not trigger R12."""
    result = _run_lint(_R12_DOC_YAML)
    assert "R12" not in result.stdout, (
        f"R12 false positive on description/comment.\nstdout: {result.stdout}"
    )


# R13 — meta-deception vocabulary in handler bodies (the canonical 5/19 leak
# was a YAML comment from inside a `handler: |` block scalar literally
# emitting "Disney cross-pollination POC" to every reader of proxy_config.yaml).

_R13_LEAK_YAML = """\
apiVersion: v1
protocol: http
address: ":1234"
commands:
  - regex: "^/proxy_config\\\\.yaml$"
    handler: |
      general_settings:
        # Watermark password in DB URL — Disney cross-pollination POC.
        database_url: postgresql://app:secret@db:5432/proxy
    statusCode: 200
"""

_R13_CLEAN_YAML = """\
apiVersion: v1
protocol: http
address: ":1234"
# Top-of-file comment mentioning honeypot/disney/POC — NOT served over wire.
# R13 must not flag these.
commands:
  - regex: "^/proxy_config\\\\.yaml$"
    handler: |
      general_settings:
        database_url: postgresql://app:secret@db:5432/proxy
    statusCode: 200
"""


def test_R13_catches_meta_vocabulary_in_handler():
    """A handler body containing 'Disney' or 'POC' or 'honeypot' must fire R13 CRITICAL."""
    result = _run_lint(_R13_LEAK_YAML)
    assert "R13" in result.stdout, (
        f"R13 didn't fire on handler-body leak.\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "CRITICAL" in result.stdout, (
        f"R13 must be CRITICAL severity.\nstdout: {result.stdout}"
    )


def test_R13_ignores_top_of_file_comments():
    """Top-of-file YAML comments are stripped by parser; R13 must NOT fire on them."""
    result = _run_lint(_R13_CLEAN_YAML)
    assert "R13" not in result.stdout, (
        f"R13 false positive on top-of-file comments.\nstdout: {result.stdout}"
    )


if __name__ == "__main__":
    r12_tests = [
        test_R12_catches_frozen_timestamp_in_handler,
        test_R12_allows_time_ago_template,
        test_R12_skips_descriptions_and_comments,
    ]
    r13_tests = [
        test_R13_catches_meta_vocabulary_in_handler,
        test_R13_ignores_top_of_file_comments,
    ]
    all_tests = [
        test_R11_catches_header_body_mismatch,
        test_R11_coherent_handler_is_clean,
        test_R11_multi_version_file_fires_warn,
    ] + r12_tests + r13_tests
    failures = 0
    for t in all_tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
        except AssertionError as e:
            print(f"  FAIL  {t.__name__}: {e}")
            failures += 1
    if failures:
        print(f"\n{failures}/{len(all_tests)} tests FAILED")
        sys.exit(1)
    else:
        print(f"\n{len(all_tests)}/{len(all_tests)} tests passed")
        sys.exit(0)
