"""Tests for the lure-shape verification harness — static-checks only."""
import sys
from pathlib import Path

import pytest

# Locate the tools/verify_lure_shape.py so we can import its functions.
TOOLS = Path(__file__).resolve().parents[2] / "tools"
sys.path.insert(0, str(TOOLS))

from verify_lure_shape import Probe, check_static_expectations  # noqa: E402


def test_probe_from_dict_minimal():
    p = Probe.from_dict({"name": "x", "method": "GET", "path": "/"})
    assert p.name == "x"
    assert p.expect_status is None


def test_check_status_match():
    p = Probe.from_dict({"name": "x", "method": "GET", "path": "/", "expect_status": 200})
    assert check_static_expectations(p, 200, {}, b"") == []
    assert "status" in check_static_expectations(p, 404, {}, b"")[0]


def test_check_status_in_list():
    p = Probe.from_dict({"name": "x", "method": "GET", "path": "/",
                         "expect_status_in": [200, 401, 403]})
    assert check_static_expectations(p, 200, {}, b"") == []
    assert check_static_expectations(p, 401, {}, b"") == []
    assert "not in" in check_static_expectations(p, 500, {}, b"")[0]


def test_check_required_keys():
    p = Probe.from_dict({"name": "x", "method": "GET", "path": "/",
                         "expect_keys": ["data", "object"]})
    assert check_static_expectations(p, 200, {"Content-Type": "application/json"},
                                     b'{"data": [], "object": "list"}') == []
    failures = check_static_expectations(p, 200, {"Content-Type": "application/json"},
                                          b'{"data": []}')
    assert any("missing keys" in f for f in failures)


def test_check_keys_only_rejects_extras():
    p = Probe.from_dict({"name": "x", "method": "GET", "path": "/",
                         "expect_keys_only": ["models"]})
    # Real Ollama /api/tags has only `models` — extras are tells.
    assert check_static_expectations(p, 200, {"Content-Type": "application/json"},
                                     b'{"models": []}') == []
    failures = check_static_expectations(p, 200, {"Content-Type": "application/json"},
                                          b'{"models": [], "role": "assistant"}')
    assert any("unexpected keys" in f for f in failures)


def test_check_forbidden_keys_catches_as63949_signature():
    """The AS63949 fleet was detected because /api/tags mixed chat-completion
    fields with the models array. This test confirms our harness catches it."""
    p = Probe.from_dict({
        "name": "ollama-tags",
        "method": "GET",
        "path": "/api/tags",
        "forbidden_keys": ["role", "content", "total_duration"],
    })
    # AS63949-style forged response (mixed endpoints):
    body = b'{"models": [], "role": "assistant", "content": "hi", "total_duration": 1234}'
    failures = check_static_expectations(p, 200, {"Content-Type": "application/json"}, body)
    assert any("FORBIDDEN" in f for f in failures)
    assert any("AS63949" in f for f in failures)


def test_check_body_contains_substrings():
    p = Probe.from_dict({"name": "x", "method": "GET", "path": "/",
                         "expect_body_contains": ["<title>", "Open WebUI"]})
    assert check_static_expectations(p, 200, {"Content-Type": "text/html"},
                                     b"<html><title>Open WebUI</title></html>") == []
    failures = check_static_expectations(p, 200, {"Content-Type": "text/html"},
                                          b"<html><title>WrongApp</title></html>")
    assert any("required substring" in f for f in failures)


def test_check_response_header_present():
    p = Probe.from_dict({"name": "x", "method": "GET", "path": "/",
                         "expect_response_headers_present": ["x-vllm-version"]})
    assert check_static_expectations(p, 200, {"X-VLLM-Version": "0.6.4"}, b"") == []
    assert "missing response header" in check_static_expectations(
        p, 200, {}, b"")[0]


# ---------------------------------------------------------------------------
# G.1 augmentations: trigger-string, timestamp freshness, cross-port uniformity
# ---------------------------------------------------------------------------

def test_check_forbidden_substrings():
    p = Probe.from_dict({
        "name": "x", "method": "GET", "path": "/",
        "forbidden_substrings": ["VULNERABLE", "wW0sffoqsk.EM"],
    })
    # Clean response — no trigger strings present
    assert check_static_expectations(p, 200, {}, b'{"ok": true}') == []
    # Tripped by trigger string embedded in response
    failures = check_static_expectations(p, 200, {}, b'{"msg": "VULNERABLE-version"}')
    assert any("FORBIDDEN substring" in f for f in failures)


def test_check_timestamp_freshness_passes_recent():
    from datetime import datetime, timezone
    fresh = datetime.now(timezone.utc).isoformat().encode()
    body = b'{"created": "' + fresh + b'"}'
    p = Probe.from_dict({"name": "x", "method": "GET", "path": "/"})
    assert check_static_expectations(p, 200, {}, body) == []


def test_check_timestamp_freshness_fails_stale():
    body = b'{"created": "2024-01-01T00:00:00Z"}'
    p = Probe.from_dict({"name": "x", "method": "GET", "path": "/"})
    failures = check_static_expectations(p, 200, {}, body)
    assert any("STALE" in f for f in failures)


def test_check_timestamp_timezone_mixed():
    body = b'{"a": "2026-05-05T10:00:00+08:00", "b": "2026-05-05T02:00:00Z"}'
    p = Probe.from_dict({"name": "x", "method": "GET", "path": "/"})
    failures = check_static_expectations(p, 200, {}, body)
    assert any("TIMEZONE MIXED" in f for f in failures)


def test_check_timestamp_consistent_timezone_passes():
    import json
    from datetime import datetime, timezone
    # Use dynamic fresh timestamps so the test doesn't go stale after 7 days
    fresh1 = datetime.now(timezone.utc).astimezone().isoformat()
    fresh2 = datetime.now(timezone.utc).astimezone().isoformat()
    body = json.dumps({"a": fresh1, "b": fresh2}).encode()
    p = Probe.from_dict({"name": "x", "method": "GET", "path": "/"})
    assert check_static_expectations(p, 200, {}, body) == []


def test_check_cross_port_uniformity_module_imports():
    """Smoke test that the function exists and is callable.
    Live-network behaviour is verified separately."""
    from verify_lure_shape import check_cross_port_uniformity
    assert callable(check_cross_port_uniformity)
