#!/usr/bin/env python3
"""Generate JA4H oracle vectors by running FoxIO's REAL to_ja4h() over a corpus.

This is a true differential oracle: each (input -> expected JA4H) pair is produced
by the canonical FoxIO reference compute (python/ja4h.py), NOT by a re-transcription.
Only the resulting data (input + expected hash strings) is committed to the repo
(tracer/testdata/ja4h_oracle_vectors.json); FoxIO's code (FoxIO License 1.1) lives
in a gitignored clone under .refs/ and is never redistributed.

Regenerate:
    git clone --depth 1 https://github.com/FoxIO-LLC/ja4 \
        tools/fingerprint-oracle/.refs/foxio-ja4
    python3 tools/fingerprint-oracle/gen_ja4h_oracle.py

The Go differential test (tracer/ja4h_diff_test.go) reads the JSON and asserts our
ComputeJA4H reproduces every expected value — so CI needs only Go, no python/tshark.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".refs", "foxio-ja4", "python"))
import ja4h as foxio_ja4h  # noqa: E402  (from the gitignored clone)

# Corpus: each case mirrors what our Go ComputeJA4H consumes — a method, an HTTP
# version, header NAMES in wire order (may include cookie/referer to exercise
# filtering), an optional Accept-Language, and an optional Cookie header value.
CORPUS = [
    {"method": "GET", "version": "HTTP/1.1",
     "headers": ["host", "user-agent", "accept", "accept-encoding", "connection"]},
    {"method": "GET", "version": "HTTP/1.1",
     "headers": ["host", "user-agent", "accept"], "accept_language": "en-US,en;q=0.9"},
    {"method": "POST", "version": "HTTP/1.1",
     "headers": ["host", "content-type", "accept-language", "cookie"],
     "accept_language": "en-US,en;q=0.9", "cookie": "b_cookie=2; a_cookie=1"},
    {"method": "POST", "version": "HTTP/1.1",
     "headers": ["host", "cookie"], "cookie": "session=abc123"},
    {"method": "GET", "version": "HTTP/1.1",
     "headers": ["host", "referer", "user-agent"]},  # referer flag + filtered
    {"method": "GET", "version": "HTTP/2",
     "headers": ["host", "user-agent"]},  # http/2 -> version 20
    {"method": "GET", "version": "HTTP/1.0",
     "headers": ["host", "user-agent"]},  # version 10
    {"method": "DELETE", "version": "HTTP/1.1", "headers": ["host"]},
    {"method": "PATCH", "version": "HTTP/1.1", "headers": ["host", "content-type"]},
    {"method": "PUT", "version": "HTTP/1.1",
     "headers": ["host", "cookie"], "cookie": "z=26; m=13; a=1"},  # multi-cookie sort
    {"method": "GET", "version": "HTTP/1.1",
     "headers": ["host"], "accept_language": "fr-CH, fr;q=0.9"},
    {"method": "GET", "version": "HTTP/1.1",
     "headers": [":method", ":path", "host", "user-agent"]},  # pseudo-headers filtered
    # > 99 headers -> clamp to 99
    {"method": "GET", "version": "HTTP/1.1",
     "headers": ["host"] + [f"x-h{i}" for i in range(120)]},
]


def reference_ja4h(case):
    hl = "http2" if case["version"] in ("HTTP/2", "HTTP/2.0") else "http1"
    x = {"method": case["method"], "version": case["version"], "hl": hl,
         "headers": list(case["headers"]), "stream": "0", "src": "", "dst": "",
         "srcport": "", "dstport": "", "protocol": "tcp"}
    if "accept_language" in case:
        x["lang"] = case["accept_language"]
    if "cookie" in case:
        x["cookies"] = case["cookie"]
    return foxio_ja4h.to_ja4h(x)["JA4H"]


def main():
    out = [{"input": c, "expected": reference_ja4h(dict(c))} for c in CORPUS]
    dest = os.path.normpath(os.path.join(HERE, "..", "..", "tracer", "testdata",
                                         "ja4h_oracle_vectors.json"))
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "w") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    print(f"wrote {len(out)} JA4H oracle vectors to {dest}")
    for v in out:
        print(f"  {v['expected']}  <- {v['input']}")


if __name__ == "__main__":
    main()
