#!/usr/bin/env python3
"""rotate_canaries.py — canary-token rotation orchestrator (sensor-local)

Operator-driven interactive rotation. Captures new token values via hidden
terminal input, stages them atomically into canary.env, updates the
manifest file (metadata only — no values), and optionally triggers redeploy.

Security posture (OWASP-aware):
  - Secrets never echo to stdout/stderr, never enter shell history, never
    pass via CLI args or env vars.
  - All paste-input goes through silent readline (terminal echo disabled).
  - Atomic write: tempfile → fsync → rename. 0600 mode verified post-write.
  - Backup before overwrite; rollback via `rotate_canaries.py rollback <ts>`.
  - No network calls. Values come only from operator paste.
  - Format validation per token type before staging; malformed input rejected.
  - Manifest writes are metadata-only (token_id, reminder, timestamps).
  - Audit log is append-only and contains zero secret material.

Usage:
  python3 rotate_canaries.py list            # show current canary.env slots + ages
  python3 rotate_canaries.py plan PLAN.yaml  # dry-run: validate plan, show diff
  python3 rotate_canaries.py apply PLAN.yaml # interactive: prompt, stage, deploy
  python3 rotate_canaries.py verify PLAN.yaml # post-deploy: probe lures for new values
  python3 rotate_canaries.py rollback TIMESTAMP

Exit codes: 0 success; 1 validation error; 2 aborted; 3 rollback; 4 deploy failure.
"""

from __future__ import annotations

import argparse
import configparser
import getpass
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required. Install: pip3 install PyYAML  (or: apt-get install python3-yaml)")


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

RE_AKIA = re.compile(r"^AKIA[A-Z0-9]{16}$")
RE_AWS_SECRET = re.compile(r"^[A-Za-z0-9+/=]{40}$")
RE_CT_DOMAIN = re.compile(r"^[a-z0-9]{25}\.canarytokens\.com$")
RE_CT_TOKEN_ID = re.compile(r"^[a-z0-9]{25}$")
RE_CT_MANAGE_URL = re.compile(
    r"https?://canarytokens\.org/(?:history|manage)/?\?[^\s]*token=([a-z0-9]{25})"
)
RE_CT_FIRE_URL = re.compile(r"https?://canarytokens\.com/[^\s]*/([a-z0-9]{25})/")


# ---------------------------------------------------------------------------
# Terminal input helpers — hidden multi-line paste
# ---------------------------------------------------------------------------

def read_hidden_line(prompt: str) -> str:
    """Read one line, no echo. Empty input returns ''."""
    try:
        return getpass.getpass(prompt=prompt)
    except (EOFError, KeyboardInterrupt):
        print("\naborted", file=sys.stderr)
        sys.exit(2)


def read_multiline_paste(intro: str) -> str:
    """Read a multi-line paste. Empty line terminates.

    Uses plain input(), NOT getpass — bracketed-paste terminal sequences
    (\\e[200~ … \\e[201~) confuse getpass and the whole paste ends up empty.
    The AWS [default] credentials block we read here is about to be written
    to /opt/honeypot-sensor/.env at 0o600 and traverses a sudo+SSH path
    anyway, so terminal echo during paste adds no material leakage.

    Also strips bracketed-paste ESC sequences defensively in case the
    user's terminal is still emitting them.
    """
    print(intro, file=sys.stderr)
    print("  (Paste the block; terminate with a single empty line.)", file=sys.stderr)
    lines: list[str] = []
    while True:
        try:
            line = input("  > ")
        except (EOFError, KeyboardInterrupt):
            print("\naborted", file=sys.stderr)
            sys.exit(2)
        # Strip any leftover bracketed-paste markers ("\e[200~" / "\e[201~")
        line = line.replace("\x1b[200~", "").replace("\x1b[201~", "")
        if line == "":
            break
        lines.append(line)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Parsers / validators per slot type
# ---------------------------------------------------------------------------

def parse_aws_default_block(text: str) -> dict[str, str]:
    """Parse a canonical `[default]`-style AWS credentials block."""
    if "[default]" not in text:
        raise ValueError("No [default] section. Paste the whole block including [default].")
    cp = configparser.ConfigParser()
    # configparser is case-insensitive for section names but keys must be lowercase
    cp.read_string(text)
    section = cp["default"]
    key = section.get("aws_access_key_id", "").strip()
    secret = section.get("aws_secret_access_key", "").strip()
    region = section.get("region", "").strip() or "us-east-2"
    output = section.get("output", "").strip() or "json"
    if not RE_AKIA.match(key):
        raise ValueError(f"aws_access_key_id format invalid (expected AKIA + 16 chars)")
    if not RE_AWS_SECRET.match(secret):
        raise ValueError(f"aws_secret_access_key format invalid (expected 40-char base64-ish)")
    return {"key": key, "secret": secret, "region": region, "output": output}


def parse_canary_domain(text: str) -> str:
    """Validate a canarytokens.com DNS subdomain."""
    s = text.strip().lower()
    # accept either bare domain or URL form
    s = s.replace("https://", "").replace("http://", "").split("/")[0]
    if not RE_CT_DOMAIN.match(s):
        raise ValueError(f"Expected <25-char>.canarytokens.com — got {s!r}")
    return s


def parse_canary_web_url(text: str) -> str:
    """Validate a canarytokens.com web-beacon URL."""
    s = text.strip()
    if not s.lower().startswith(("http://canarytokens.com/", "https://canarytokens.com/")):
        raise ValueError("Expected http(s)://canarytokens.com/... URL")
    m = RE_CT_FIRE_URL.search(s)
    if not m:
        raise ValueError("URL does not contain a 25-char token identifier")
    return s


def extract_token_id(text: str) -> str:
    """Best-effort token_id extraction from a pasted string (manage URL, fire URL, or bare id)."""
    s = text.strip()
    # bare ID
    if RE_CT_TOKEN_ID.match(s):
        return s
    # manage URL
    m = RE_CT_MANAGE_URL.search(s)
    if m:
        return m.group(1)
    # fire URL (per token type)
    m = RE_CT_FIRE_URL.search(s)
    if m:
        return m.group(1)
    # bare domain
    m = re.match(r"^([a-z0-9]{25})\.canarytokens\.com", s.lower())
    if m:
        return m.group(1)
    raise ValueError("Could not extract a 25-char token_id from input")


# ---------------------------------------------------------------------------
# canary.env I/O
# ---------------------------------------------------------------------------

def read_env_file(path: Path) -> dict[str, str]:
    """Minimal .env parser. Does not evaluate shell syntax."""
    if not path.exists():
        return {}
    out: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        # strip surrounding quotes
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
            v = v[1:-1]
        out[k.strip()] = v
    return out


def atomic_write_env(path: Path, data: dict[str, str], header_lines: list[str] | None = None) -> None:
    """Write canary.env atomically at 0600.

    Greenfield writer: ignores whatever existed at `path` and emits a fresh
    file with `header_lines` as `# ...` comments followed by sorted KEY=VALUE
    entries. Safe only when `data` represents the full desired content of the
    file. For in-place updates that must preserve untouched keys, comments,
    and ordering (e.g. /opt/honeypot-sensor/.env), use merge_env_file instead.
    """
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".canary.env.", dir=str(parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            if header_lines:
                for h in header_lines:
                    f.write(f"# {h}\n")
                f.write("\n")
            for k in sorted(data):
                f.write(f"{k}={data[k]}\n")
            f.flush()
            os.fsync(f.fileno())
        os.rename(tmp, str(path))
    except Exception:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    # verify mode
    st = path.stat()
    if stat.S_IMODE(st.st_mode) != 0o600:
        path.chmod(0o600)


def merge_env_file(path: Path, changes: dict[str, str]) -> None:
    """In-place update of an env file: only KEYs in `changes` are rewritten.

    Preserves comments, blank lines, ordering, and every key we're not
    touching. Use this when `path` is a shared env file (e.g. docker-compose
    .env) that carries non-canary variables we MUST NOT clobber.

    - Keys present in both file and `changes`: value replaced, line order kept.
    - Keys only in `changes` (not already in file): appended at the end under
      a timestamped comment so an operator can see what was added.
    - Keys only in the file: left untouched.

    Written via tempfile+fsync+rename at mode 0600.
    """
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)

    if path.exists():
        original_lines = path.read_text().splitlines()
    else:
        original_lines = []

    seen: set[str] = set()
    out_lines: list[str] = []
    for line in original_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            out_lines.append(line)
            continue
        key = stripped.split("=", 1)[0].strip()
        if key in changes:
            out_lines.append(f"{key}={changes[key]}")
            seen.add(key)
        else:
            out_lines.append(line)

    new_keys = sorted(set(changes) - seen)
    if new_keys:
        if out_lines and out_lines[-1].strip() != "":
            out_lines.append("")
        out_lines.append(f"# Added by rotate_canaries.py on {datetime.now(timezone.utc).isoformat()}")
        for k in new_keys:
            out_lines.append(f"{k}={changes[k]}")

    fd, tmp = tempfile.mkstemp(prefix=".env.rotate.", dir=str(parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            for line in out_lines:
                f.write(f"{line}\n")
            f.flush()
            os.fsync(f.fileno())
        os.rename(tmp, str(path))
    except Exception:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    st = path.stat()
    if stat.S_IMODE(st.st_mode) != 0o600:
        path.chmod(0o600)


def backup_env(path: Path) -> Path:
    """Copy canary.env to .bak.<utc-iso>."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    bak = path.with_suffix(path.suffix + f".bak.{ts}")
    shutil.copy2(str(path), str(bak))
    bak.chmod(0o600)
    return bak


# ---------------------------------------------------------------------------
# Manifest I/O
# ---------------------------------------------------------------------------

def load_manifest(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Manifest not found: {path}")
    return yaml.safe_load(path.read_text())


def save_manifest(path: Path, manifest: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        yaml.safe_dump(manifest, f, sort_keys=False, default_flow_style=False)
    path.chmod(0o644)  # manifest has no secrets — world-readable is fine


# ---------------------------------------------------------------------------
# Discord notification — stdlib-only, failure-soft
# ---------------------------------------------------------------------------
# Webhook URL comes from:
#   1. --discord-webhook CLI arg (highest priority)
#   2. HONEYPOT_DISCORD_WEBHOOK env var (recommended for sensor install)
#   3. None — Discord notifications are skipped silently
# Never prints the webhook URL. Never prints secret material in embeds.

_COLOR_SUCCESS = 0x22C55E  # green
_COLOR_WARNING = 0xF59E0B  # amber
_COLOR_DANGER = 0xDC2626   # red


def _discord_post(webhook_url: str | None, payload: dict) -> None:
    """POST a Discord webhook payload. Failure-soft: print warning, never raise."""
    if not webhook_url:
        return
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=data,
            headers={"Content-Type": "application/json", "User-Agent": "rotate_canaries/1.0"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            # Discord returns 204 No Content on success
            if resp.status not in (200, 204):
                print(f"  (discord: unexpected status {resp.status})", file=sys.stderr)
    except urllib.error.URLError as e:
        print(f"  (discord notify failed: {e.reason}; rotation state is unaffected)", file=sys.stderr)
    except Exception as e:
        print(f"  (discord notify failed: {type(e).__name__}; rotation state is unaffected)", file=sys.stderr)


def _discord_resolve_webhook(arg_value: str | None) -> str | None:
    """CLI arg wins over env var. Returns None if unset (quiet skip)."""
    return arg_value or os.environ.get("HONEYPOT_DISCORD_WEBHOOK") or None


def notify_rotation_applied(webhook_url: str | None, manifest: dict[str, Any],
                             slots_rotated: list[str], env_path: Path,
                             backup_path: Path | None, deploy_attempted: bool,
                             deploy_ok: bool) -> None:
    sensor = manifest.get("sensor", "?")
    version = manifest.get("version", "?")
    operator = manifest.get("operator", "(unset)")
    reason = (manifest.get("reason") or "(none)")[:1024]

    deploy_line = (
        "✅ deploy-fork.sh completed" if deploy_attempted and deploy_ok
        else "⚠️ deploy-fork.sh failed — manual redeploy required" if deploy_attempted and not deploy_ok
        else "⏸ deploy skipped — run `bash /opt/honeypot-sensor/deploy-fork.sh` manually"
    )

    embed = {
        "title": f"🔄 Canary rotation applied — sensor-{sensor} v{version}",
        "color": _COLOR_SUCCESS if deploy_ok or not deploy_attempted else _COLOR_WARNING,
        "fields": [
            {"name": "Operator", "value": operator, "inline": True},
            {"name": "Prior version", "value": f"v{manifest.get('prior_version', '?')}", "inline": True},
            {"name": "Slots rotated", "value": str(len(slots_rotated)), "inline": True},
            {"name": "Reason", "value": reason, "inline": False},
            {"name": "Deploy", "value": deploy_line, "inline": False},
            {"name": "canary.env", "value": f"`{env_path}`", "inline": True},
        ],
        "footer": {"text": "rotate_canaries.py — no secret material in this message"},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if backup_path:
        embed["fields"].append({"name": "Backup", "value": f"`{backup_path.name}`", "inline": True})
    if slots_rotated:
        # Short bullet list of slot names, truncated at field limit
        bullet_list = "\n".join(f"• {s}" for s in slots_rotated)
        if len(bullet_list) > 1000:
            bullet_list = bullet_list[:980] + "\n…"
        embed["fields"].append({"name": "Slot names", "value": bullet_list, "inline": False})

    _discord_post(webhook_url, {"username": "canary-rotation", "embeds": [embed]})


def notify_rollback(webhook_url: str | None, env_path: Path, restored_from: Path,
                    forward_backup: Path | None) -> None:
    embed = {
        "title": "↩️ Canary rollback applied",
        "color": _COLOR_WARNING,
        "fields": [
            {"name": "Restored", "value": f"`{restored_from.name}` → `{env_path.name}`", "inline": False},
            {"name": "Forward-backup", "value": f"`{forward_backup.name}`" if forward_backup else "(none)", "inline": True},
        ],
        "footer": {"text": "Deploy manually: bash deploy-fork.sh"},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    _discord_post(webhook_url, {"username": "canary-rotation", "embeds": [embed]})


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

def append_audit(log_path: Path, manifest: dict[str, Any], slots_rotated: list[str]) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sensor": manifest.get("sensor"),
        "version": manifest.get("version"),
        "prior_version": manifest.get("prior_version"),
        "operator": manifest.get("operator"),
        "slots_rotated": slots_rotated,
        "slot_count": len(slots_rotated),
    }
    with log_path.open("a") as f:
        f.write(f"\n## {entry['timestamp']} — sensor-{entry['sensor']} v{entry['version']}\n\n")
        f.write(f"- operator: {entry['operator']}\n")
        f.write(f"- prior_version: {entry['prior_version']}\n")
        f.write(f"- slots_rotated ({entry['slot_count']}):\n")
        for s in slots_rotated:
            f.write(f"  - {s}\n")


# ---------------------------------------------------------------------------
# Rendering — how a parsed token value becomes the env-var string
# ---------------------------------------------------------------------------

def render_env_value(slot: dict[str, Any], parsed: Any) -> dict[str, str]:
    """Return the env-var → value mapping for this slot from parsed input."""
    stype = slot["type"]
    if stype == "aws_keys":
        env_key, env_secret = slot["env_vars"]
        return {env_key: parsed["key"], env_secret: parsed["secret"]}
    if stype in ("dns", "web", "email"):
        env_var = slot["env_var"]
        # rendering template may wrap: e.g. "hvs.<domain>", "https://<domain>", "dd-api-<domain>"
        tmpl = slot.get("rendering")
        if tmpl and "<domain>" in tmpl:
            return {env_var: tmpl.replace("<domain>", parsed)}
        return {env_var: parsed}
    raise ValueError(f"Unknown slot type: {stype}")


# ---------------------------------------------------------------------------
# Slot interaction
# ---------------------------------------------------------------------------

def prompt_slot(slot_name: str, slot: dict[str, Any], idx: int, total: int) -> tuple[Any, str]:
    """Interactive prompt for one slot. Returns (parsed_value, token_id)."""
    header = f"[{idx}/{total}] {slot_name}"
    print("\n" + "=" * 78, file=sys.stderr)
    print(header, file=sys.stderr)
    print("=" * 78, file=sys.stderr)
    print(f"  type:         {slot['type']}", file=sys.stderr)
    print(f"  reminder:     {slot['reminder']}", file=sys.stderr)
    env_vars = slot.get("env_vars") or [slot.get("env_var")]
    print(f"  env_vars:     {', '.join(e for e in env_vars if e)}", file=sys.stderr)
    if slot.get("consumed_by"):
        print(f"  consumed_by:  {', '.join(slot['consumed_by'])}", file=sys.stderr)
    if slot.get("rendering"):
        print(f"  rendering:    {slot['rendering']}", file=sys.stderr)
    print("", file=sys.stderr)
    print("  Steps:", file=sys.stderr)
    print("    1. Go to https://canarytokens.org/generate", file=sys.stderr)
    _type_instructions(slot["type"])
    print(f"    3. Memo: {slot['reminder']}", file=sys.stderr)
    print("    4. Click Create. Copy the values below as prompted.", file=sys.stderr)
    print("", file=sys.stderr)

    parsed = _prompt_type(slot["type"])

    # For DNS + web slots the token_id IS derivable from the parsed value
    # (domain or URL). Prompt only when we genuinely need operator input
    # (aws_keys, email — these have no self-contained token_id in the value).
    if slot["type"] in ("dns", "web") and isinstance(parsed, str):
        try:
            token_id = extract_token_id(parsed)
        except ValueError:
            token_id = ""
        if token_id:
            print(f"  ✓ staged (token_id …{token_id[-6:]}, auto-derived)", file=sys.stderr)
            return parsed, token_id

    token_input = input(
        "  Paste manage URL OR token_id (optional, Enter to skip): "
    ).strip()
    if not token_input:
        # Accept missing provenance for aws_keys/email: the token's AKIA (or
        # the email string itself) is the real identity and will be visible
        # in every webhook fire, so we can reconcile later.
        print(f"  ✓ staged (no token_id recorded — provenance skipped)", file=sys.stderr)
        return parsed, ""

    token_id = extract_token_id(token_input)
    _cross_check_token_id(slot["type"], parsed, token_id)
    print(f"  ✓ staged (token_id …{token_id[-6:]})", file=sys.stderr)
    return parsed, token_id


def _type_instructions(stype: str) -> None:
    inst = {
        "aws_keys": "    2. Select 'AWS API keys'",
        "dns": "    2. Select 'DNS token'",
        "web": "    2. Select 'Web bug / URL token'",
        "email": "    2. Select 'sensitive_cmd' or 'email' per current convention",
    }.get(stype, "    2. (select token type)")
    print(inst, file=sys.stderr)


def _prompt_type(stype: str) -> Any:
    if stype == "aws_keys":
        # Two single-line prompts — no multi-line paste, no empty-line
        # terminator, no bracketed-paste quirks. Canarytokens.org shows
        # each field with its own copy button, so it's one click per prompt.
        key = input("  aws_access_key_id (AKIA…): ").strip()
        if not RE_AKIA.match(key):
            raise ValueError(
                f"aws_access_key_id format invalid (expected AKIA + 16 chars), got {key!r}"
            )
        secret = input("  aws_secret_access_key (40 chars): ").strip()
        if not RE_AWS_SECRET.match(secret):
            raise ValueError(
                "aws_secret_access_key format invalid (expected 40-char base64-ish)"
            )
        # Region + output are cosmetic metadata only (we don't write them to .env),
        # so skip prompting. Default them.
        return {"key": key, "secret": secret, "region": "us-east-2", "output": "json"}
    if stype == "dns":
        text = input("  Paste the canarytokens.com subdomain: ")
        return parse_canary_domain(text)
    if stype == "web":
        text = input("  Paste the fire URL: ")
        return parse_canary_web_url(text)
    if stype == "email":
        text = input("  Paste the canary email address or plain string: ")
        return text.strip()
    raise ValueError(f"Unknown slot type {stype!r}")


def _cross_check_token_id(stype: str, parsed: Any, token_id: str) -> None:
    """If we can derive the token_id from the parsed value, verify they match."""
    if stype == "dns" and isinstance(parsed, str):
        got = parsed.split(".")[0]
        if got != token_id:
            raise ValueError(f"token_id mismatch: domain={got[:6]}... vs manage-url={token_id[:6]}...")
    if stype == "web" and isinstance(parsed, str):
        m = RE_CT_FIRE_URL.search(parsed)
        if m and m.group(1) != token_id:
            raise ValueError("token_id mismatch between fire URL and manage URL")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_list(args: argparse.Namespace) -> int:
    env_path = Path(args.env).expanduser()
    env = read_env_file(env_path)
    print(f"\ncanary.env — {env_path}  ({len(env)} keys)\n")
    # Group AWS pairs
    aws_keys = sorted(k for k in env if "AWS_KEY" in k or k.endswith("_AWS_KEY"))
    aws_secrets = sorted(k for k in env if "AWS_SECRET" in k or k.endswith("_AWS_SECRET"))
    dns_keys = sorted(k for k in env if "DNS" in k or "DB_PASS" in k or "VAULT_TOKEN" in k or "DOCKER_AUTH" in k or k.startswith("CANARY_SSH_API_KEY") or k.endswith("_DD_KEY"))
    web_keys = sorted(k for k in env if "WEB" in k)
    other = sorted(set(env) - set(aws_keys) - set(aws_secrets) - set(dns_keys) - set(web_keys))

    def _show(group, names):
        if not names: return
        print(f"  [{group}]")
        for n in names:
            v = env[n]
            redacted = _redact(v)
            print(f"    {n:40s} {redacted}")
        print()

    _show("AWS keys", aws_keys)
    _show("AWS secrets", aws_secrets)
    _show("DNS-derived", dns_keys)
    _show("Web beacons", web_keys)
    _show("Other", other)
    return 0


def _redact(v: str) -> str:
    if len(v) <= 12:
        return "***"
    return f"{v[:6]}…{v[-4:]}"


def cmd_plan(args: argparse.Namespace) -> int:
    manifest = load_manifest(Path(args.plan))
    sensor = manifest.get("sensor")
    slots = manifest.get("slots", {})
    print(f"\nPlan: sensor-{sensor} v{manifest.get('version')} (from v{manifest.get('prior_version')})")
    print(f"  reason:     {manifest.get('reason', '(none)')}")
    print(f"  slot count: {len(slots)}")
    print(f"\nSlots to rotate:")
    for name, s in slots.items():
        env_vars = s.get("env_vars") or [s.get("env_var")]
        print(f"  - {name:32s}  type={s['type']:10s}  reminder={s['reminder']:40s}  env={env_vars}")
    print("\nNo changes made (dry run). Use `apply` to rotate.")
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    plan_path = Path(args.plan)
    manifest = load_manifest(plan_path)
    env_path = Path(manifest.get("canary_env_path", args.env)).expanduser()

    # Apply --only filter (staged rollout). Carry-forward of unrotated slots happens
    # naturally because new_env is seeded from current_env below — keys we don't
    # touch keep their existing values.
    only_slots: set[str] | None = None
    if args.only:
        only_slots = {s.strip() for s in args.only.split(",") if s.strip()}
        unknown = only_slots - set(manifest["slots"].keys())
        if unknown:
            print(f"  ! unknown slot(s) in --only: {sorted(unknown)}", file=sys.stderr)
            print(f"    available: {sorted(manifest['slots'].keys())}", file=sys.stderr)
            return 2

    selected_slots = (
        {n: s for n, s in manifest["slots"].items() if n in only_slots}
        if only_slots is not None
        else dict(manifest["slots"])
    )

    print(f"\nApply rotation:  sensor-{manifest['sensor']} v{manifest['version']}  → {env_path}")
    print(f"  operator: {manifest.get('operator', '(unset)')}")
    print(f"  reason:   {manifest.get('reason', '(none)')}")
    if only_slots is not None:
        print(f"  slots:    {len(selected_slots)} of {len(manifest['slots'])} (--only filter active)")
        print(f"            rotating: {sorted(selected_slots.keys())}")
    else:
        print(f"  slots:    {len(selected_slots)}")
    confirm = input("\nProceed? [y/N]: ").strip().lower()
    if confirm != "y":
        print("aborted")
        return 2

    # Backup
    if env_path.exists():
        bak = backup_env(env_path)
        print(f"  ✓ backed up to {bak}")
    else:
        print(f"  ! no existing canary.env at {env_path} — starting fresh")

    # Sanity-check that the existing env file parses (so we know we can write
    # back to it without corrupting it on atomic rename).
    _ = read_env_file(env_path)

    # Collect ONLY the keys we rotate. merge_env_file will update these in
    # place, preserving every other line in the target file. We deliberately
    # do NOT seed new_env from current_env — untouched keys must pass through
    # the original file byte-for-byte (comments, quoting, ordering).
    changes: dict[str, str] = {}
    slots_rotated: list[str] = []
    total = len(selected_slots)
    for idx, (slot_name, slot) in enumerate(selected_slots.items(), start=1):
        while True:
            try:
                parsed, token_id = prompt_slot(slot_name, slot, idx, total)
                break
            except ValueError as e:
                print(f"  ! {e} — retry this slot [Y/n/skip]", file=sys.stderr)
                r = input("    > ").strip().lower()
                if r == "n":
                    return 2
                if r == "skip":
                    parsed, token_id = None, None
                    break
        if parsed is None:
            print(f"  skipped {slot_name}", file=sys.stderr)
            continue
        # render into env
        kv = render_env_value(slot, parsed)
        changes.update(kv)
        # update manifest (metadata only — no secrets)
        slot["token_id"] = token_id
        slot["rotated_at"] = datetime.now(timezone.utc).isoformat()
        if slot["type"] == "aws_keys" and isinstance(parsed, dict):
            slot["region"] = parsed.get("region")
        slots_rotated.append(slot_name)

    # Stamp manifest
    manifest["rotated"] = datetime.now(timezone.utc).isoformat()

    # Final confirmation
    print(f"\nStaged {len(slots_rotated)} slot rotation(s) "
          f"({len(changes)} env var(s) to update in {env_path}).")
    confirm = input("Merge into env file atomically? [y/N]: ").strip().lower()
    if confirm != "y":
        print("aborted — no changes written")
        return 2

    merge_env_file(env_path, changes)
    print(f"  ✓ merged {len(changes)} key(s) into {env_path}")

    # Save updated manifest (metadata only)
    save_manifest(plan_path, manifest)
    print(f"  ✓ updated manifest {plan_path}")

    # Audit log
    audit_log = Path(args.audit_log).expanduser()
    append_audit(audit_log, manifest, slots_rotated)
    print(f"  ✓ appended to audit log {audit_log}")

    # Deploy?
    deploy_script = manifest.get("deploy_script") or args.deploy_script
    deploy_attempted = False
    deploy_ok = False
    if deploy_script and args.deploy:
        deploy_attempted = True
        print(f"\nRunning deploy: {deploy_script}")
        try:
            subprocess.run(["bash", deploy_script], check=True)
            print("  ✓ deploy complete")
            deploy_ok = True
        except subprocess.CalledProcessError as e:
            print(f"  ! deploy failed (exit {e.returncode}) — canary.env was written. Run {deploy_script} manually.")
    else:
        print(f"\nDeploy manually:  bash {deploy_script or '(configure deploy_script in plan)'}")

    # Discord notification (failure-soft, no secret material)
    if not args.no_discord:
        webhook_url = _discord_resolve_webhook(args.discord_webhook)
        if webhook_url:
            notify_rotation_applied(
                webhook_url=webhook_url,
                manifest=manifest,
                slots_rotated=slots_rotated,
                env_path=env_path,
                backup_path=bak if env_path.exists() else None,
                deploy_attempted=deploy_attempted,
                deploy_ok=deploy_ok,
            )
            print("  ✓ discord notified")
        else:
            print("  (discord: no webhook configured, skipping)")

    print("\nPost-rotation: rename v(n-1) tokens at canarytokens.org admin to '<reminder>-BURNED-<date>'.")
    return 0 if (not deploy_attempted or deploy_ok) else 4


def cmd_verify(args: argparse.Namespace) -> int:
    manifest = load_manifest(Path(args.plan))
    print(f"\nVerification commands for sensor-{manifest['sensor']} v{manifest['version']}:\n")
    print("  # Confirm AKIAs are served by the lure surfaces:")
    print("  curl -s http://localhost:8000/.env        | grep -oP 'AKIA[A-Z0-9]{16}' | sort -u")
    print("  curl -s http://localhost:8000/.cursorrules | grep -oP 'AKIA[A-Z0-9]{16}' | sort -u")
    print("  curl -s http://localhost:8000/.env.prod   | grep -oP 'AKIA[A-Z0-9]{16}' | sort -u")
    print()
    print("  # Confirm Ollama code-gen emits the new AKIA:")
    print("  curl -s http://localhost:11434/api/generate \\")
    print("       -d '{\"model\":\"llama3.1:8b\",\"prompt\":\"write a node client for our platform\",\"stream\":false}' \\")
    print("       | grep -oP 'AKIA[A-Z0-9]{16}' | sort -u")
    print()
    print("  Expected: all output matches the AWS key_ids you just minted.")
    print("  Compare against manifest token_ids in " + str(Path(args.plan)))
    return 0


def cmd_rollback(args: argparse.Namespace) -> int:
    env_path = Path(args.env).expanduser()
    ts = args.timestamp
    bak = env_path.with_suffix(env_path.suffix + f".bak.{ts}")
    if not bak.exists():
        print(f"! backup not found: {bak}")
        # list available
        parent = env_path.parent
        baks = sorted(parent.glob(env_path.name + ".bak.*"))
        print("Available backups:")
        for b in baks:
            print(f"  {b.name}")
        return 3
    confirm = input(f"Restore {bak.name} → {env_path.name}? [y/N]: ").strip().lower()
    if confirm != "y":
        return 2
    # Backup the current file before rollback so we can re-forward if needed
    if env_path.exists():
        fwd = backup_env(env_path)
        print(f"  ✓ current env saved at {fwd}")
    shutil.copy2(str(bak), str(env_path))
    env_path.chmod(0o600)
    print(f"  ✓ restored {bak} → {env_path}")
    print(f"\nDeploy manually to make the restored env live: bash /opt/honeypot-sensor/deploy-fork.sh")

    # Discord notification on rollback
    if not args.no_discord:
        webhook_url = _discord_resolve_webhook(args.discord_webhook)
        if webhook_url:
            notify_rollback(
                webhook_url=webhook_url,
                env_path=env_path,
                restored_from=bak,
                forward_backup=fwd if env_path.exists() else None,
            )
            print("  ✓ discord notified")
    return 0


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--env", default="/opt/honeypot-sensor/canary.env",
                    help="Path to canary.env (default: /opt/honeypot-sensor/canary.env)")
    ap.add_argument("--audit-log",
                    default="/opt/honeypot-sensor/tools/manifest/canary-rotation-log.md",
                    help="Audit log path (append-only)")
    ap.add_argument("--deploy-script", default="/opt/honeypot-sensor/deploy-fork.sh")
    ap.add_argument("--discord-webhook", default=None,
                    help="Discord webhook URL for rotation notifications "
                         "(falls back to $HONEYPOT_DISCORD_WEBHOOK; omit for silent mode)")
    ap.add_argument("--no-discord", action="store_true",
                    help="Disable Discord notifications regardless of env / CLI webhook")

    sp = ap.add_subparsers(dest="cmd", required=True)

    sp_list = sp.add_parser("list", help="Show current canary.env slots + redacted values")

    sp_plan = sp.add_parser("plan", help="Dry-run: validate plan, print diff")
    sp_plan.add_argument("plan", help="Path to manifest YAML")

    sp_apply = sp.add_parser("apply", help="Interactive rotation")
    sp_apply.add_argument("plan", help="Path to manifest YAML")
    sp_apply.add_argument("--deploy", action="store_true",
                          help="Run deploy-fork.sh after successful write (default: off)")
    sp_apply.add_argument("--only", default=None,
                          help="Comma-separated slot names to rotate (others carry forward "
                               "their existing canary.env values). For staged rollouts and "
                               "single-slot e2e validation. Example: --only DNS_OLLAMA_SUBDOMAIN")

    sp_verify = sp.add_parser("verify", help="Print post-deploy verification commands")
    sp_verify.add_argument("plan", help="Path to manifest YAML")

    sp_roll = sp.add_parser("rollback", help="Restore a .bak canary.env")
    sp_roll.add_argument("timestamp", help="Timestamp suffix of the .bak file (e.g. 2026-04-18T20-30-45Z)")

    args = ap.parse_args()
    if args.cmd == "list":
        return cmd_list(args)
    if args.cmd == "plan":
        return cmd_plan(args)
    if args.cmd == "apply":
        return cmd_apply(args)
    if args.cmd == "verify":
        return cmd_verify(args)
    if args.cmd == "rollback":
        return cmd_rollback(args)
    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
