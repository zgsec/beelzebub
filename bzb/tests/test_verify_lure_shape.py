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
