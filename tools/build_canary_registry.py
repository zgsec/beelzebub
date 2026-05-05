#!/usr/bin/env python3
"""build_canary_registry.py — canonical canary registry generator.

Walks every tools/manifest/canary-manifest.*.yaml and emits (or updates)
tools/canary-registry.yaml — the single source of truth that the
webhook receiver uses to resolve a fire's `token_reminder` to
(owner, sensor, slot_name, status). Without this, slot-level attribution
depends on a human-typed memo alone; one typo (see `ffra-ollama-…` on
2026-04-19) breaks the chain silently.

Registry schema (single entry):

    id:                 stable cross-rotation identifier
                         `<sensor>.<slot_name_lower>.<version>`
    reminder:           primary lookup key — already 1:1 unique per slot
                         across the whole fleet and operator-controlled
    owner:              who minted the token
    sensor:             fra | ewr | sea | jp
    slot_name:          AWS_KEY_MCP, DNS_OLLAMA_SUBDOMAIN, …
    type:               aws_keys | dns | web | email
    version:            rotation version (2, 3, …)
    rotation_cohort:    YYYYMM (from reminder suffix)
    status:             active | burned | retired
    consumed_by:        list of beelzebub config paths
    token_id:           optional — canarytokens.org 25-char ID, lazy
    minted_at:          optional — when the token was first minted
    notes:              optional free-form

Commit-safe. Secrets (AWS secret_access_key, canarytokens auth=…) are
NEVER in this file; they live in the per-sensor canary.env / .env and
in the operator's canarytokens.org admin login respectively.

Usage:
    python3 tools/build_canary_registry.py
    python3 tools/build_canary_registry.py --registry /path/to/other.yaml
    python3 tools/build_canary_registry.py --dry-run

Idempotent: re-running preserves any fields that were filled in by
subsequent operator edits (notably token_id, minted_at, notes) — only
fields derivable from the manifest (reminder, sensor, slot_name, type,
consumed_by, status) are overwritten.
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    sys.exit("ERROR: pyyaml not installed — pip install pyyaml")

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_REGISTRY = _REPO_ROOT / "tools" / "canary-registry.yaml"
_MANIFESTS_GLOB = "manifest/canary-manifest.*.yaml"

_RE_COHORT = re.compile(r"-v(\d+)-(\d{6})$")


def _parse_cohort(reminder: str) -> tuple[str | None, str | None]:
    """Extract (version, YYYYMM) from a reminder string; return (None, None) on mismatch."""
    m = _RE_COHORT.search(reminder)
    return (m.group(1), m.group(2)) if m else (None, None)


def _manifest_to_registry_entries(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten a rotation manifest into individual registry entries.

    Decoy-estate manifests (e.g., canary-manifest.meridian-edge.yaml) set a
    top-level `decoy_company` that propagates to every slot, plus optional
    per-slot `decoy_asset` / `placement` / `content_lineage`. Per-sensor
    manifests (ewr/fra/sin/coop) leave decoy_* unset.
    """
    sensor = manifest.get("sensor")
    version = manifest.get("version")
    operator = manifest.get("operator")
    decoy_company = manifest.get("decoy_company")
    default_status = manifest.get("default_status")  # e.g., "planned" for stub
    if not sensor:
        return []

    entries: list[dict[str, Any]] = []
    for slot_name, slot in (manifest.get("slots") or {}).items():
        reminder = slot.get("reminder")
        if not reminder:
            # Unreadable slot — skip with a warn so the operator notices.
            print(f"WARN: manifest slot {slot_name!r} has no reminder, skipping",
                  file=sys.stderr)
            continue
        ver, cohort = _parse_cohort(reminder)
        entry: dict[str, Any] = {
            # Stable ID: sensor + slot + version. Burnt tokens from older
            # versions stay in the registry with their own ID.
            "id": f"{sensor}.{slot_name.lower()}.v{version or ver or '?'}",
            "reminder": reminder,
            "owner": operator or "unknown",
            "sensor": sensor,
            "slot_name": slot_name,
            "type": slot.get("type"),
            "version": version or (int(ver) if ver and ver.isdigit() else None),
            "rotation_cohort": cohort,
            "status": slot.get("status") or default_status or "active",
            "consumed_by": list(slot.get("consumed_by") or []),
            # Lazy / nice-to-have fields. None → filled in later (from a
            # fire payload or manual operator update).
            "token_id": slot.get("token_id"),
            "minted_at": slot.get("rotated_at"),
        }
        if slot.get("notes"):
            entry["notes"] = slot["notes"]

        # Decoy-estate lineage. Top-level decoy_company applies to all slots
        # in the manifest; per-slot fields override or specify finer detail.
        if decoy_company:
            entry["decoy_company"] = decoy_company
        if slot.get("decoy_company"):
            entry["decoy_company"] = slot["decoy_company"]  # per-slot override
        if slot.get("decoy_asset"):
            entry["decoy_asset"] = slot["decoy_asset"]
        if slot.get("placement"):
            entry["placement"] = slot["placement"]
        if slot.get("content_lineage"):
            entry["content_lineage"] = list(slot["content_lineage"])

        entries.append(entry)
    return entries


def _merge(existing: list[dict[str, Any]],
           incoming: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge `incoming` entries into `existing`, keyed on `reminder`.

    Manifest-derived fields (reminder, sensor, slot_name, type, version,
    rotation_cohort, consumed_by, id) are refreshed from `incoming`.
    Operator-curated fields (token_id, minted_at, notes, status) are
    preserved from `existing` unless they are still None/default.

    New reminders become new entries. Retired reminders (present in
    `existing` but not in `incoming`) keep their entries but flip to
    `status: burned` — we NEVER delete registry rows. An old token
    that still fires after rotation is a first-class signal.
    """
    by_reminder = {e["reminder"]: e for e in existing}
    seen_incoming: set[str] = set()

    for new in incoming:
        rem = new["reminder"]
        seen_incoming.add(rem)
        if rem in by_reminder:
            old = by_reminder[rem]
            # Preserve curated fields; refresh manifest-derived fields.
            merged = dict(new)
            for curated in ("token_id", "minted_at", "notes"):
                if old.get(curated) not in (None, "", []):
                    merged[curated] = old[curated]
            # Status: preserve operator override (burned/retired) but allow
            # manifest to push 'planned' → 'active' on first deploy.
            if old.get("status") in ("burned", "retired"):
                merged["status"] = old["status"]
            by_reminder[rem] = merged
        else:
            by_reminder[rem] = new

    # Anything in `existing` but NOT in `incoming` = retired from manifests.
    # Flip status to 'burned' (if not already retired/burned) but keep the row.
    for rem, old in by_reminder.items():
        if rem not in seen_incoming and old.get("status") == "active":
            old["status"] = "burned"

    # Sort by (sensor, slot_name, version) so diffs are human-readable.
    return sorted(
        by_reminder.values(),
        key=lambda e: (e.get("sensor", ""), e.get("slot_name", ""),
                       e.get("version") or 0),
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog=__doc__)
    ap.add_argument("--registry", type=Path, default=_DEFAULT_REGISTRY,
                    help=f"Output path (default: {_DEFAULT_REGISTRY})")
    ap.add_argument("--manifests-dir", type=Path,
                    default=_REPO_ROOT / "tools",
                    help=f"Manifests parent directory (default: {_REPO_ROOT / 'tools'})")
    ap.add_argument("--dry-run", action="store_true",
                    help="Print merged output, don't write.")
    args = ap.parse_args()

    # Load existing registry if present
    existing: list[dict[str, Any]] = []
    if args.registry.exists():
        try:
            loaded = yaml.safe_load(args.registry.read_text()) or {}
        except yaml.YAMLError as exc:
            sys.exit(f"ERROR: existing registry is malformed YAML: {exc}")
        existing = list(loaded.get("entries") or [])

    # Load every manifest under the manifests dir
    incoming: list[dict[str, Any]] = []
    manifests = sorted(args.manifests_dir.glob(_MANIFESTS_GLOB))
    if not manifests:
        sys.exit(f"ERROR: no manifests found at {args.manifests_dir}/{_MANIFESTS_GLOB}")
    for mpath in manifests:
        try:
            m = yaml.safe_load(mpath.read_text()) or {}
        except yaml.YAMLError as exc:
            print(f"WARN: skipping malformed manifest {mpath}: {exc}", file=sys.stderr)
            continue
        incoming.extend(_manifest_to_registry_entries(m))

    merged = _merge(existing, incoming)

    output = {
        "version": 1,
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "generator": "tools/build_canary_registry.py",
        "entries": merged,
    }

    if args.dry_run:
        yaml.safe_dump(output, sys.stdout, sort_keys=False, default_flow_style=False)
        print(f"\n# dry-run: {len(merged)} total entries ({len(incoming)} from manifests, "
              f"{len(existing)} prior).", file=sys.stderr)
        return 0

    tmp = args.registry.with_suffix(args.registry.suffix + ".tmp")
    tmp.write_text(yaml.safe_dump(output, sort_keys=False, default_flow_style=False))
    tmp.replace(args.registry)
    print(f"wrote {args.registry} ({len(merged)} entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
