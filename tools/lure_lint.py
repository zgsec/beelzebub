"""Lure deception-leak linter.

Catches the classes of fingerprint leak discovered in the 2026-05-06
sniff-test conformance run before they ship to a sensor:

  R1  Fictional Server header — value not in lure_realism.yaml allowlist.
  R2  Banned headers (X-Platform, X-Honeypot, etc.) appear on any command.
  R3  Hardcoded X-Request-Id literals — must use ${request.uuid*} runtime
      substitution or omit the header entirely.
  R4  Method-gating gaps — a command whose path matches a known POST-only
      or GET-only endpoint of the real product (per lure_realism.yaml)
      must declare `method:`.
  R5  Catch-all 404 — every commands list must end with a `.*` or `^.*$`
      regex matching all unmatched paths and returning 4xx (defaults the
      404 against the "200 to a random path" Censys honeypot detector).
  R6  Jinja2 in rendered output — `configurations-rendered/` files must be
      free of `{{ ... }}`; literal templates would leak to attackers if
      the render step didn't substitute. Source configs ARE permitted to
      have templates (they go through bzb persona render).
  R7  Unrendered Beelzebub runtime tokens — `${session.*}` / `${captured.*}`
      / `${request.*}` outside header/body fields (e.g., in `regex:` or
      `name:`) will never substitute and emit literally.

Per-line waiver: append `# lure-lint: ignore-R<N>` to suppress one rule on
that line. Use sparingly and document why.

Usage:
    python tools/lure_lint.py [path ...]
    python tools/lure_lint.py --help

Exit code:
    0  no violations
    1  one or more violations (CI gate fails)

If no paths given, lints every `*.yaml` under `configurations/services/` and
`personas/<persona>/lures/`. Each violation prints one line with
`file:line: rule  message`. Add `--summary` for a final pass/fail rollup.

Designed to run pre-commit, in CI, and as a hard gate inside
`bzb persona render`. Stdlib + PyYAML only.
"""
from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

try:
    import yaml
except ImportError:
    print("PyYAML required: pip install pyyaml", file=sys.stderr)
    sys.exit(2)


REPO_ROOT = Path(__file__).resolve().parent.parent
REALISM_YAML = Path(__file__).resolve().parent / "lure_realism.yaml"


@dataclass
class Violation:
    file: Path
    line: int
    rule: str
    message: str

    def __str__(self) -> str:
        rel = self.file.relative_to(REPO_ROOT) if self.file.is_relative_to(REPO_ROOT) else self.file
        return f"{rel}:{self.line}: {self.rule}  {self.message}"


def load_realism() -> dict:
    return yaml.safe_load(REALISM_YAML.read_text())


# ---------------------------------------------------------------------------
# Rule helpers
# ---------------------------------------------------------------------------

# A header line in a lure config: matches the YAML pattern
#     - "Header-Name: value"
# inside a `headers:` block.
HEADER_LINE_RE = re.compile(r'^\s*-\s*"([A-Za-z][A-Za-z0-9-]*):\s*([^"]*)"')

# regex line: matches `- regex: "..."` capturing the regex content.
REGEX_LINE_RE = re.compile(r'^\s*-\s*regex:\s*"((?:[^"\\]|\\.)*)"')

# method line: matches `    method: "GET"` etc.
METHOD_LINE_RE = re.compile(r'^\s*method:\s*"([A-Z]+)"')

# Hex-only request ID (8+ hex chars) — flags hardcoded literals.
HEX_LITERAL_RE = re.compile(r'^[a-f0-9_-]{8,}$', re.IGNORECASE)

# UUID format
UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)


def detect_service(path: Path) -> str | None:
    """Map a lure file name to a service-type key in lure_realism.yaml."""
    name = path.stem  # e.g. "litellm-4000", "ollama-11434"
    if name.startswith("ollama-"):
        return "ollama"
    if name.startswith(("litellm-", "openai-", "vllm-", "lmdeploy-")):
        return "openai-compatible"
    if name.startswith("influxdb-"):
        return "influxdb"
    if name.startswith("http-"):
        # http-8888 is Open WebUI in our codebase
        return "open-webui"
    if name.startswith("mcp-"):
        return "mcp"
    return None


def iter_yaml_files(paths: list[Path]) -> Iterator[Path]:
    """Expand the inputs to a flat list of yaml files. Skips `*.bak`,
    rendered output, and the realism allowlist itself."""
    for p in paths:
        if p.is_file() and p.suffix in (".yaml", ".yml"):
            yield p
        elif p.is_dir():
            for sub in sorted(p.rglob("*.yaml")):
                if sub.name == REALISM_YAML.name:
                    continue
                if "configurations-rendered" in sub.parts:
                    continue
                if sub.suffix == ".bak":
                    continue
                yield sub


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

def rule_r1_server(lines: list[str], path: Path, realism: dict) -> Iterator[Violation]:
    """Server: header value must contain a known-real product name."""
    allow = [s.lower() for s in realism.get("known_servers", [])]
    for i, line in enumerate(lines, 1):
        m = HEADER_LINE_RE.match(line)
        if not m:
            continue
        name, value = m.group(1), m.group(2).strip()
        if name.lower() != "server":
            continue
        # Strip Jinja2 + ${} tokens from value before checking
        stripped = re.sub(r"\{\{[^}]*\}\}", "", value)
        stripped = re.sub(r"\$\{[^}]*\}", "", stripped)
        stripped = stripped.strip().lower()
        if not stripped:
            continue  # value is templated — caller handles via render context
        if not any(known in stripped for known in allow):
            yield Violation(
                path, i, "R1",
                f'Server: "{value}" — not in lure_realism known_servers allowlist '
                "(probable fictional product name)",
            )


def rule_r2_banned_headers(lines: list[str], path: Path, realism: dict) -> Iterator[Violation]:
    """Headers in the banned list must not appear on any command."""
    banned = {h.lower() for h in realism.get("banned_headers", [])}
    for i, line in enumerate(lines, 1):
        m = HEADER_LINE_RE.match(line)
        if not m:
            continue
        if m.group(1).lower() in banned:
            yield Violation(
                path, i, "R2",
                f'header "{m.group(1)}" is banned (leaks persona internals)',
            )


def rule_r3_hardcoded_request_id(lines: list[str], path: Path, realism: dict) -> Iterator[Violation]:
    """X-Request-Id values must use ${request.uuid*} or be absent."""
    banned_lits = set(realism.get("banned_request_ids", []))
    for i, line in enumerate(lines, 1):
        m = HEADER_LINE_RE.match(line)
        if not m:
            continue
        if m.group(1).lower() != "x-request-id":
            continue
        value = m.group(2).strip()
        # Acceptable: contains ${request.*} substitution
        if "${request." in value:
            continue
        # Literal hex/uuid/etc. — flag.
        # Strip prefix like "req_" before checking the suffix.
        suffix = re.sub(r"^[A-Za-z]+_", "", value)
        if (HEX_LITERAL_RE.match(suffix) or UUID_RE.match(suffix)
                or value in banned_lits):
            yield Violation(
                path, i, "R3",
                f'X-Request-Id: "{value}" — hardcoded literal; '
                "use ${request.uuid_short} or ${request.uuid}",
            )


def rule_r4_method_gates(lines: list[str], path: Path, realism: dict) -> Iterator[Violation]:
    """Commands matching known method-restricted endpoints must declare `method:`.

    Walks the file linearly: tracks the current command's regex and whether
    a `method:` field appears before the next regex / EOF. If the regex
    matches a service expected_methods entry, missing method: is a violation.
    """
    service = detect_service(path)
    if service is None:
        return
    expected = realism.get("expected_methods", {}).get(service, {})
    if not expected:
        return

    # Build a flat list of (regex_pattern, expected_method) pairs.
    expected_pairs: list[tuple[str, str]] = []
    for verb, paths in expected.items():
        for p in paths:
            expected_pairs.append((p, verb))

    # Walk the file, tracking command boundaries.
    cur_regex: str | None = None
    cur_regex_line: int = 0
    cur_has_method: bool = False

    def flush(end_line: int) -> Iterator[Violation]:
        if cur_regex is None:
            return
        # Does this regex match any known method-restricted endpoint?
        for pat, expected_verb in expected_pairs:
            if cur_regex == pat or cur_regex.replace(r"\\", "\\") == pat:
                if not cur_has_method:
                    yield Violation(
                        path, cur_regex_line, "R4",
                        f'regex "{cur_regex}" should be method-gated to '
                        f'{expected_verb} (real {service} behavior)',
                    )
                return

    for i, line in enumerate(lines, 1):
        rm = REGEX_LINE_RE.match(line)
        if rm:
            yield from flush(i - 1)
            cur_regex = rm.group(1)
            cur_regex_line = i
            cur_has_method = False
            continue
        if cur_regex is not None and METHOD_LINE_RE.match(line):
            cur_has_method = True

    yield from flush(len(lines))


def rule_r5_catchall_404(lines: list[str], path: Path, realism: dict) -> Iterator[Violation]:
    """The commands: list must include a catch-all `.*` or `^.*$` regex
    returning 4xx (closes the "200 to random path" Censys detector).

    Only applies to protocols that serve HTTP-shaped requests (http, mcp,
    ollama). Skipped for ssh, tcp, telnet, etc.

    Implementation: find every `regex:` line, check whether at least one
    is a catch-all and is followed by a 4xx statusCode within the next
    ~15 lines.
    """
    # Skip files that aren't service configs (e.g., persona.yaml has no commands).
    if path.name in ("persona.yaml", "canaries.yaml", "node.yaml") or "/nodes/" in str(path):
        return
    if "/templates/" in str(path) or path.name.endswith(".j2"):
        return

    text = "\n".join(lines)
    if "commands:" not in text:
        return  # not a service config

    # Only HTTP-ish protocols need a catch-all 404. ssh/tcp/telnet have no
    # concept of "random path" — skip them entirely.
    proto_m = re.search(r"^protocol:\s*\"?([a-z]+)\"?\s*$", text, re.MULTILINE)
    if proto_m and proto_m.group(1) not in ("http", "mcp", "ollama"):
        return

    has_catchall = False
    catchall_404 = False
    for i, line in enumerate(lines, 1):
        rm = REGEX_LINE_RE.match(line)
        if not rm:
            continue
        regex = rm.group(1)
        if regex in ('.*', '^.*$'):
            has_catchall = True
            # Look ahead for statusCode within ~15 lines.
            for j in range(i, min(i + 15, len(lines))):
                if "statusCode:" in lines[j]:
                    sc_line = lines[j].split("statusCode:", 1)[1].strip()
                    try:
                        if 400 <= int(sc_line) < 500:
                            catchall_404 = True
                            break
                    except ValueError:
                        pass

    # Some configs use fallbackCommand: instead of a regex stanza.
    has_fallback_404 = False
    if re.search(r"^fallbackCommand:", text, re.MULTILINE):
        # Look for a statusCode 4xx anywhere AFTER the fallbackCommand line
        # (the block extends to the next top-level YAML key OR end of file).
        m = re.search(r"^fallbackCommand:(.*?)(?=^[A-Za-z])|^fallbackCommand:(.*)\Z",
                      text, re.DOTALL | re.MULTILINE)
        if m:
            block = m.group(1) or m.group(2) or ""
            sc = re.search(r"statusCode:\s*(\d+)", block)
            if sc and 400 <= int(sc.group(1)) < 500:
                has_fallback_404 = True

    if not (catchall_404 or has_fallback_404):
        marker = "no catch-all" if not has_catchall else "catch-all is not 4xx"
        yield Violation(
            path, len(lines), "R5",
            f"commands list lacks a 4xx catch-all ({marker}); "
            "Censys honeypot detector flags 200-to-random-path",
        )


def rule_r6_jinja_in_rendered(lines: list[str], path: Path, realism: dict) -> Iterator[Violation]:
    """Files under `configurations-rendered/` are mounted directly into the
    container — they must NOT contain unsubstituted `{{ ... }}` templates.

    Source configs (configurations/services/, personas/.../lures/) are
    expected to contain Jinja2 — they go through bzb persona render.
    """
    if "configurations-rendered" not in str(path):
        return
    for i, line in enumerate(lines, 1):
        if "{{" not in line or "}}" not in line:
            continue
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        yield Violation(
            path, i, "R6",
            "unrendered `{{ ... }}` in rendered config — render step skipped or broken",
        )


def rule_r7_runtime_token_misplaced(lines: list[str], path: Path, realism: dict) -> Iterator[Violation]:
    """Beelzebub runtime tokens (${request.*}, ${session.*}, ${captured.*})
    only substitute in `headers:` and `handler:` (response body).
    Their appearance in `regex:` or `name:` means the literal string is
    used as-is and won't substitute, which is almost certainly a mistake.
    """
    for i, line in enumerate(lines, 1):
        if not re.search(r"\$\{(request|session|captured)\.", line):
            continue
        # OK: appearing in headers or handler context.
        # Trim leading whitespace + leading `- "Header:` or similar.
        stripped = line.strip()
        if stripped.startswith(("- regex:", "name:", "- name:")):
            yield Violation(
                path, i, "R7",
                "runtime token ${request|session|captured.*} placed in "
                "`regex:` or `name:` — those fields don't substitute; "
                "tokens only work in handler/headers values",
            )


RULES = [
    rule_r1_server,
    rule_r2_banned_headers,
    rule_r3_hardcoded_request_id,
    rule_r4_method_gates,
    rule_r5_catchall_404,
    rule_r6_jinja_in_rendered,
    rule_r7_runtime_token_misplaced,
]

# Per-rule severity. CRITICAL fires on every check; WARN can be downgraded
# to non-fatal in --warn-only mode (default for R4 today, since legacy
# configs have many uncovered method-gated endpoints).
SEVERITY = {
    "R1": "CRITICAL",
    "R2": "CRITICAL",
    "R3": "CRITICAL",
    "R4": "WARN",
    "R5": "CRITICAL",
    "R6": "CRITICAL",
    "R7": "CRITICAL",
}


WAIVER_RE = re.compile(r"#\s*lure-lint:\s*ignore-(R\d)")


def lint_file(path: Path, realism: dict) -> list[Violation]:
    text = path.read_text()
    lines = text.split("\n")
    out: list[Violation] = []
    for rule in RULES:
        for v in rule(lines, path, realism):
            # Per-line waiver: skip if the violation's line carries
            # `# lure-lint: ignore-R<N>`.
            if 0 < v.line <= len(lines):
                m = WAIVER_RE.search(lines[v.line - 1])
                if m and m.group(1) == v.rule:
                    continue
            out.append(v)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", type=Path,
                    help="files or directories to lint (default: configurations/services + personas/*/lures)")
    ap.add_argument("--summary", action="store_true", help="print pass/fail summary at end")
    ap.add_argument("--rule", action="append", default=[],
                    help="only run named rule (R1..R7); can repeat")
    ap.add_argument("--strict", action="store_true",
                    help="treat WARN-severity rules as CRITICAL (default: only CRITICAL fails CI)")
    args = ap.parse_args()

    if not args.paths:
        args.paths = [
            REPO_ROOT / "configurations" / "services",
            REPO_ROOT / "personas",
        ]

    realism = load_realism()
    files = list(iter_yaml_files(args.paths))
    if not files:
        print("no yaml files found", file=sys.stderr)
        return 2

    selected = set(args.rule) if args.rule else None
    critical = 0
    warn = 0
    for f in files:
        for v in lint_file(f, realism):
            if selected and v.rule not in selected:
                continue
            sev = SEVERITY.get(v.rule, "CRITICAL")
            print(f"{v}  [{sev}]")
            if sev == "CRITICAL" or args.strict:
                critical += 1
            else:
                warn += 1

    if args.summary:
        msg = f"\nlure_lint: {critical} critical, {warn} warning across {len(files)} files"
        print(msg if (critical + warn) else f"\nlure_lint: clean across {len(files)} files")

    return 1 if critical else 0


if __name__ == "__main__":
    sys.exit(main())
