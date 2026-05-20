"""Lure deception-leak linter.

Rules:
  R1  Server header value not in lure_realism.yaml allowlist.
  R2  Banned headers (X-Platform, X-Honeypot, etc.) on any command.
  R3  Hardcoded X-Request-Id literals — must use ${request.uuid*} or omit.
  R4  Method-gating gaps on known POST-only / GET-only product endpoints.
  R5  Missing catch-all 404 — every commands list must end with `.*` or `^.*$`
      returning 4xx (defends against "200 to a random path" honeypot detector).
  R6  Jinja2 `{{ ... }}` in rendered output. Source configs are exempt.
  R7  Unrendered Beelzebub runtime tokens (`${session.*}`, `${captured.*}`,
      `${request.*}`) outside header/body fields — they emit literally.
  R8  Banned credential literals — AWS docs example AKIA + secret pair, and
      other strings that secret scanners flag as fake-by-default. Anything
      shipped under one of these names is a tell, not a tripwire.
  R9  Same canary placeholder reused across N+ leak points in one file.
      When render-canaries.sh substitutes a single ${VAR}, every leak point
      emits the *same* secret value — that uniformity is itself the tell.
      Use distinct canary placeholders per leak path, or 404 the redundant
      ones. Threshold: 5+ uses across distinct `handler:` / response bodies.
  R10 Other template-fingerprint leaks in rendered output:
        - `{% ... %}` Jinja statement blocks (R6 only catches expressions)
        - `<% ... %>` ERB-style templating
        - `{name.attr}` Python str.format style (e.g., `{canaryTokens.aws_key}`)
      These read as half-rendered templates to attentive observers / AI agents.
      Source configs are exempt; rendered output (`configurations-rendered/`,
      `out/<slug>/<node>/persona/lures/`) must be clean. Caught the 2026-05-18
      operator-flagged `{canaryTokens.X}` leak in SSH-2222 LLM prompt.
  R11 MCP protocolVersion coherence — scanner detectable version mismatch.
      Two checks:
        - Per-command: if a command ships an `X-MCP-Version: V` response header,
          its `handler:` body must contain `"protocolVersion":"V"`. Header/body
          skew is trivially detectable (one HTTP response, two fields).
          (CRITICAL on mismatch)
        - File-wide: if any two handlers in the same file emit different
          `"protocolVersion":"..."` values, flag the inconsistency.
          (WARN — legacy lures may intentionally speak two protocol generations)
  R12 Frozen ISO timestamps in handler bodies — a scanner re-probing weeks
      later sees identical "last activity" values, trivially detectable as a
      honeypot tell. Use ${time.ago.<N><s|m|h|d>} or ${time.now} instead.
      Skips description/summary/notes/comment fields and YAML comments.
      (WARN — some timestamps are legitimately persona-locked; use waiver)

Per-line waiver: append `# lure-lint: ignore-R<N>` to suppress one rule
(works for R1..R12+).

Exit 0 on clean, 1 on violations. With no paths, lints every YAML under
`configurations/services/` and `personas/<persona>/lures/`.
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


HEADER_LINE_RE = re.compile(r'^\s*-\s*"([A-Za-z][A-Za-z0-9-]*):\s*([^"]*)"')
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


def _is_rendered_output(path: Path) -> bool:
    """A path is 'rendered output' if it lives under any post-render dir.

    Two known render targets:
      - `configurations-rendered/...`  — final, on-sensor (post envsubst)
      - `out/<slug>/<node>/persona/lures/...` — bzb persona render output
                                                (post Jinja, pre envsubst)

    Source-of-truth dirs (`personas/<slug>/lures/`, `configurations/services/`)
    are NOT rendered output — they're EXPECTED to contain Jinja + ${VAR}.
    The fingerprint rules (R6, R10) only fire on rendered output.

    The 2026-05-18 operator catch found that R6 was only checking
    configurations-rendered/, so {{ }} leaks in bzb-render output skipped
    the gate. Path check now covers both layers.
    """
    p = str(path)
    if "configurations-rendered" in p:
        return True
    # bzb persona render: `out/<slug>/<node>/persona/lures/<lure>.yaml`
    parts = path.parts
    try:
        out_idx = parts.index("out")
    except ValueError:
        return False
    # Expect: out / <slug> / <node> / persona / lures / <file>
    return len(parts) > out_idx + 4 and parts[out_idx + 3] == "persona" \
        and parts[out_idx + 4] == "lures"


def rule_r6_jinja_in_rendered(lines: list[str], path: Path, realism: dict) -> Iterator[Violation]:
    """Rendered output must NOT contain unsubstituted `{{ ... }}` Jinja
    expressions. Source configs (personas/.../lures/, configurations/services/)
    are expected to contain Jinja — they go through `bzb persona render`.

    Covers both layers:
      - configurations-rendered/ (post envsubst, final on-sensor)
      - out/<slug>/<node>/persona/lures/ (post bzb Jinja render, pre envsubst)

    A `{{ }}` leak at either layer means the render step skipped or broke
    on this template — half-rendered output to the wire is a Disney tell.
    """
    if not _is_rendered_output(path):
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


# R8: Banned credential literals.
# Map of (literal-or-regex, severity-message) — strings that, when shipped in
# a lure, immediately tell secret-scanners (and observant attackers) the
# credential is fake. Add freely as new "fake-by-default" patterns are found.
BANNED_LITERALS: dict[str, str] = {
    "AKIAIOSFODNN7EXAMPLE":
        "AWS documentation example access key — on every secret-scanner blocklist",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY":
        "AWS documentation example secret key — on every secret-scanner blocklist",
    "AKIAJDOEAEEXAMPLEKEY":
        "AWS docs example AKIA — on every secret-scanner blocklist",
    "12345678-1234-1234-1234-123456789012":
        "Microsoft docs placeholder GUID — on every secret-scanner blocklist",
    "00000000-0000-0000-0000-000000000000":
        "null GUID — recognized as placeholder by every scanner",
    "ghp_1234567890abcdefghijklmnopqrstuvwxyz":
        "GitHub PAT example shape — used in docs, recognized as placeholder",
    "xK9mN2pR5sT8vW1yA4bC7dE0fG3hI6jK":
        "JWT/encryption-key shape that has shipped in our own configs as a static literal — replace with a real canary or remove",
    "aB3cD5eF7gH9iJ1kL3mN5oP7qR9sT1uV":
        "encryption-key shape that has shipped as a static literal in our configs — replace with a real canary or remove",
}


def rule_r8_banned_literals(lines: list[str], path: Path, realism: dict) -> Iterator[Violation]:
    """Scan every non-comment line for known fake-by-default credential
    literals. Even one occurrence breaks the deception — secret scanners
    (gitleaks, trufflehog) match these patterns by name as "tutorial
    examples", not real keys, so attackers never bother trying them.
    """
    for i, raw in enumerate(lines, 1):
        # Skip pure comment lines; embedded '#' inside a string is fine.
        stripped = raw.lstrip()
        if stripped.startswith("#"):
            continue
        for literal, why in BANNED_LITERALS.items():
            if literal in raw:
                yield Violation(
                    path, i, "R8",
                    f"banned literal `{literal}` — {why}",
                )


# R9: same canary placeholder reused excessively in one file.
PLACEHOLDER_RE = re.compile(r"\$\{([A-Z][A-Z0-9_]*)\}")
R9_THRESHOLD = 5
# Some placeholders are inherently single-value-per-env (DNS subdomain,
# vault address); reuse across many leak points is realism, not a tell.
# Skip these from R9 reuse-counting.
R9_REUSE_OK = {
    # DNS-token-as-hostname is a single canary by design.
    re.compile(r".*_CANARY_DNS$"),
    re.compile(r".*_CANARY_DOMAIN$"),
    # Web-bug URLs are single canaries by design.
    re.compile(r".*_CANARY_WEB(_BUG)?(_[A-Z]+)?$"),
}


def _r9_skip(name: str) -> bool:
    return any(p.match(name) for p in R9_REUSE_OK)


def rule_r9_placeholder_reuse(lines: list[str], path: Path, realism: dict) -> Iterator[Violation]:
    """Count how many lines reference each ${PLACEHOLDER}. Above the
    threshold, render emits the *same* secret value at all those points —
    a real ops env almost never reuses one credential across more than a
    handful of distinct config files / formats.

    Counting by line is a proxy for distinct leak points; one handler with
    multiple placeholder references on its line counts once.
    """
    counts: dict[str, list[int]] = {}
    for i, raw in enumerate(lines, 1):
        stripped = raw.lstrip()
        if stripped.startswith("#"):
            continue
        seen_on_line: set[str] = set()
        for m in PLACEHOLDER_RE.finditer(raw):
            name = m.group(1)
            if _r9_skip(name):
                continue
            if name in seen_on_line:
                continue
            seen_on_line.add(name)
            counts.setdefault(name, []).append(i)
    for name, line_nums in counts.items():
        if len(line_nums) >= R9_THRESHOLD:
            yield Violation(
                path, line_nums[0], "R9",
                f"${{{name}}} reused across {len(line_nums)} leak points "
                f"(lines {','.join(str(n) for n in line_nums[:6])}"
                f"{'...' if len(line_nums) > 6 else ''}); "
                f"render produces the same value at all of them — "
                f"introduce distinct canary placeholders or 404 the redundant paths",
            )


# R10: additional template-fingerprint leaks in rendered output.
# R6 catches the `{{ expression }}` Jinja shape. R10 catches the OTHER
# half-rendered template fingerprints that show up when a templating
# layer fails or wasn't wired:
#
#   {% statement %}     — Jinja control-flow leftover (block/raw/etc.)
#   <% erb %>           — ERB-style templating (Ruby / EJS / etc.)
#   {name.attribute}    — Python str.format / Mustache field access. The
#                         2026-05-18 catch found `{canaryTokens.aws_key}`
#                         in SSH-2222's LLM prompt — `substituteTokens()`
#                         only handles {{UPPER}} on Lures/EnvVars maps,
#                         NOT on plugin.prompt, so these leaked literally.
#
# All three are "doesn't look like real production output" signals.

R10_PATTERNS = [
    # Jinja control-flow (R6's sibling — expression vs statement)
    (re.compile(r"\{%[^%]*%\}"), "Jinja statement"),
    # ERB-style
    (re.compile(r"<%[^%]*%>"), "ERB-style"),
    # Python str.format-style field access:  `{ident.attr}`  (1+ digits OK).
    # Must avoid matching:
    #   - JSON `{"key":"value"}` shapes — those don't have `ident.ident`
    #   - Legitimate Beelzebub runtime tokens `${request.X}` / `${session.X}` /
    #     `${captured.X}` — exclude via negative lookbehind on `$`
    # Restrict to lowercase-letter-starts, no nested braces, no whitespace,
    # no quotes — covers the 2026-05-18 `{canaryTokens.aws_key}` leak shape.
    (
        re.compile(r"(?<!\$)\{[a-z][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*\}"),
        "Python format field access",
    ),
]


def rule_r10_template_fingerprints(
    lines: list[str], path: Path, realism: dict
) -> Iterator[Violation]:
    """Additional template-fingerprint leaks beyond R6's `{{ }}` shape.

    Only fires in rendered output (post Jinja, post envsubst). Source
    configs may legitimately contain `{% raw %}` blocks or other Jinja
    statements; rendered output should not.
    """
    if not _is_rendered_output(path):
        return
    for i, line in enumerate(lines, 1):
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        for pat, kind in R10_PATTERNS:
            m = pat.search(line)
            if not m:
                continue
            yield Violation(
                path, i, "R10",
                f"{kind} template fingerprint `{m.group(0)}` in rendered output "
                f"— reads as half-rendered template; the renderer's substitution "
                f"step skipped this or the wrong placeholder syntax was used",
            )


# R11: MCP protocolVersion coherence.
# A single HTTP response carries both an X-MCP-Version response header and a
# "protocolVersion" field inside the JSON body.  When these two values differ,
# any scanner reading the response can fingerprint the fake server in one
# request — the mismatch is trivially deterministic.
#
# Two checks:
#   (a) Per-command: X-MCP-Version header value must equal protocolVersion in body.
#   (b) File-wide: all handlers in a file must emit the same protocolVersion.

_R11_HEADER_RE = re.compile(
    r"""^["']?\s*X-MCP-Version\s*:\s*([^\s"']+)""", re.IGNORECASE
)
_R11_BODY_RE = re.compile(r'"protocolVersion"\s*:\s*"([^"]+)"')


def rule_r11_mcp_version_coherence(
    lines: list[str], path: Path, realism: dict
) -> Iterator[Violation]:
    """R11: X-MCP-Version header must match protocolVersion in response body.

    Also warns when a file emits more than one distinct protocolVersion across
    its handler strings (file-wide consistency check).
    """
    # We need to parse the YAML structure to associate headers with handlers.
    try:
        import yaml as _yaml  # already imported at module level via `yaml`
        parsed = _yaml.safe_load("\n".join(lines))
    except Exception:
        return

    if not isinstance(parsed, dict):
        return

    commands = parsed.get("commands") or []
    raw_text = "\n".join(lines)

    # (a) Per-command header-vs-body check
    for cmd_idx, cmd in enumerate(commands):
        if not isinstance(cmd, dict):
            continue
        headers = cmd.get("headers") or []
        handler = cmd.get("handler") or ""
        if not isinstance(handler, str):
            continue

        header_v: str | None = None
        for h in headers:
            if not isinstance(h, str):
                continue
            m = _R11_HEADER_RE.match(h.lstrip("- ").strip())
            if m:
                header_v = m.group(1).strip()
                break

        if header_v is None:
            continue  # no X-MCP-Version header on this command

        body_m = _R11_BODY_RE.search(handler)
        if body_m is None:
            continue  # handler has header but no protocolVersion body field — not our problem here

        body_v = body_m.group(1)
        if body_v != header_v:
            # Find the line number of the handler in the raw text so the
            # violation points somewhere useful.  Fall back to 0.
            handler_line = 0
            regex_val = cmd.get("regex", "")
            for li, ln in enumerate(lines, 1):
                if isinstance(regex_val, str) and regex_val and regex_val in ln:
                    handler_line = li
                    break
            yield Violation(
                path, handler_line, "R11",
                f"command[{cmd_idx}] regex={regex_val!r}: "
                f"X-MCP-Version header is {header_v!r} but body protocolVersion is {body_v!r} "
                f"— scanner reads both from the same HTTP response",
            )

    # (b) File-wide: collect all distinct protocolVersion values in any handler
    all_versions = set(_R11_BODY_RE.findall(raw_text))
    if len(all_versions) > 1:
        yield Violation(
            path, 0, "R11",
            f"file emits multiple distinct protocolVersion values: "
            f"{sorted(all_versions)} — inconsistent across handlers is a fingerprint",
        )


def rule_r12_no_frozen_timestamps(lines: list[str], path: Path, realism: dict) -> Iterator[Violation]:
    """R12: handler response bodies must not contain literal ISO timestamps.

    Use ${time.now}, ${time.ago.<N><s|m|h|d>} (past), or
    ${time.in.<N><s|m|h|d>} (future, added 2026-05-20) for plausible drift.

    Rationale: a scanner re-probing weeks later sees identical "last activity"
    or "expires_at" values — a trivially detectable honeypot tell.

    Skips:
      - YAML comment lines (# ...)
      - description/summary/notes/comment fields (not over-the-wire content)
      - Lines that already contain ${time.*} substitutions

    Severity: WARN — some timestamps are legitimately persona-locked (e.g.
    founded_year, a specific past incident in the show-bible). Use a
    `# lure-lint: ignore-R12` waiver to suppress individual lines.
    """
    _FROZEN_TS_RE = re.compile(
        r'"([a-zA-Z_]+)"\s*:\s*"(20\d{2}-\d{2}-\d{2}T[\d:.+Z-]+)"'
    )
    _DOC_FIELD_RE = re.compile(
        r'^\s*(description|summary|notes?|comment|label|title|message)\s*:', re.IGNORECASE
    )

    for line_no, line in enumerate(lines, start=1):
        stripped = line.lstrip()
        # Skip comment lines
        if stripped.startswith("#"):
            continue
        # Skip documentation fields
        if _DOC_FIELD_RE.match(stripped):
            continue
        # Skip lines that already contain ${time.*} (already templated)
        if "${time." in line:
            continue
        for m in _FROZEN_TS_RE.finditer(line):
            field, ts = m.group(1), m.group(2)
            yield Violation(
                path, line_no, "R12",
                f"frozen timestamp in handler "
                f"(field={field!r}, value={ts!r}) — "
                f"use ${{time.ago.<duration>}} for past or "
                f"${{time.in.<duration>}} for future drift; "
                f"re-probers see identical values as a honeypot tell",
            )


def rule_r13_no_meta_deception_vocabulary(lines: list[str], path: Path, realism: dict) -> Iterator[Violation]:
    """R13: handler response bodies must not contain meta-deception vocabulary
    that names the project methodology to an attacker.

    Forbidden tokens inside `handler:` block scalars:
      honeypot, decoy, lure, canary, watermark, show.bible, cross.pollination,
      poc, disney, play.along, act.as

    Rationale (per feedback_no_meta_terms_in_llm_prompts +
    feedback_no_disney_persona_name memories): when the served response
    contains "Disney cross-pollination POC" or similar internal-methodology
    text, every read by an attacker fingerprints the persona. The
    canonical-leak case the 2026-05-19 audit caught was the LiteLLM
    proxy_config.yaml handler emitting a YAML comment from inside its
    block-scalar body.

    Implementation: re-parse the YAML and inspect each command's `handler:`
    string. Lines outside handler bodies (e.g. file-level YAML comments,
    `description:` fields) are NOT served and not flagged.

    Severity: CRITICAL.
    """
    _FORBIDDEN = re.compile(
        r'\b(disney|cross.pollination|show.bible|honeypot|decoy|watermark|poc|play.along|act\s+as)\b',
        re.IGNORECASE,
    )
    try:
        doc = yaml.safe_load("\n".join(lines))
    except yaml.YAMLError:
        return  # parse errors are R6 territory, not R13

    if not isinstance(doc, dict):
        return
    commands = doc.get("commands") or []
    if not isinstance(commands, list):
        return

    for cmd_idx, cmd in enumerate(commands):
        if not isinstance(cmd, dict):
            continue
        handler = cmd.get("handler")
        if not isinstance(handler, str):
            continue
        for m in _FORBIDDEN.finditer(handler):
            # Compute approximate file line: walk lines until we find the
            # handler's content. Fall back to 0 if not found.
            line_no = 0
            token = m.group(0)
            lines_in_handler = handler[: m.start()].count("\n")
            # Locate the handler block start by regex on the cmd's first key
            regex_val = cmd.get("regex", "")
            for i, ln in enumerate(lines, start=1):
                if regex_val and f'regex: "{regex_val}"' in ln or (regex_val and f"regex: '{regex_val}'" in ln):
                    line_no = i + lines_in_handler + 1
                    break
            yield Violation(
                path, line_no, "R13",
                f"meta-deception vocabulary {token!r} in handler body "
                f"(cmd[{cmd_idx}], regex={regex_val[:50]!r}) — "
                f"this text is served over the wire; remove or rephrase. "
                f"See [[feedback_no_disney_persona_name]] + "
                f"[[feedback_no_meta_terms_in_llm_prompts]]",
            )


RULES = [
    rule_r1_server,
    rule_r2_banned_headers,
    rule_r3_hardcoded_request_id,
    rule_r4_method_gates,
    rule_r5_catchall_404,
    rule_r6_jinja_in_rendered,
    rule_r7_runtime_token_misplaced,
    rule_r8_banned_literals,
    rule_r9_placeholder_reuse,
    rule_r10_template_fingerprints,
    rule_r11_mcp_version_coherence,
    rule_r12_no_frozen_timestamps,
    rule_r13_no_meta_deception_vocabulary,
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
    "R8": "CRITICAL",
    "R9": "WARN",
    "R10": "CRITICAL",
    "R11": "CRITICAL",  # per-command header/body skew; WARN for file-wide multi-version
    "R12": "WARN",      # frozen timestamps; WARN allows persona-locked values via waiver
    "R13": "CRITICAL",  # meta-deception vocabulary in over-the-wire handler bodies
}


# Waiver matches R<digits> — supports R8, R9, R10+ as new rules land.
WAIVER_RE = re.compile(r"#\s*lure-lint:\s*ignore-(R\d+)")


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
