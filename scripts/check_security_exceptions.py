#!/usr/bin/env python3
"""Fail CI when RustSec exception policy drifts or outlives its review window."""

from __future__ import annotations

from datetime import date
from pathlib import Path
import re
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[1]
EXCEPTIONS = ROOT / "security-exceptions.toml"
DENY = ROOT / "deny.toml"
AUDIT = ROOT / ".cargo" / "audit.toml"
RUSTSEC = re.compile(r"RUSTSEC-\d{4}-\d{4}\Z")
REQUIRED_TEXT_FIELDS = ("id", "scope", "reason", "owner", "expires")


def load_toml(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def advisory_ids(path: Path) -> list[str]:
    values = load_toml(path).get("advisories", {}).get("ignore", [])
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise ValueError(f"{path.name} advisories.ignore must be a list of strings")
    return values


def report_duplicates(name: str, ids: list[str], errors: list[str]) -> None:
    duplicates = sorted({advisory_id for advisory_id in ids if ids.count(advisory_id) > 1})
    if duplicates:
        errors.append(f"{name} contains duplicate advisory IDs: {', '.join(duplicates)}")


def main() -> int:
    errors: list[str] = []
    try:
        entries = load_toml(EXCEPTIONS).get("exception", [])
        deny_ids = advisory_ids(DENY)
        audit_ids = advisory_ids(AUDIT)
    except (OSError, tomllib.TOMLDecodeError, ValueError) as error:
        print(f"Security exception validation failed:\n- {error}")
        return 1

    if not isinstance(entries, list) or not entries:
        errors.append("security-exceptions.toml must contain at least one [[exception]] entry")
        entries = []

    ids = [entry.get("id", "") for entry in entries if isinstance(entry, dict)]
    report_duplicates("security-exceptions.toml", ids, errors)
    report_duplicates("deny.toml", deny_ids, errors)
    report_duplicates(".cargo/audit.toml", audit_ids, errors)

    expected = set(ids)
    if expected != set(deny_ids):
        errors.append("security-exceptions.toml and deny.toml must list the same advisory IDs")
    if expected != set(audit_ids):
        errors.append("security-exceptions.toml and .cargo/audit.toml must list the same advisory IDs")

    today = date.today()
    expiries: list[date] = []
    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            errors.append(f"exception entry {index} must be a TOML table")
            continue
        advisory_id = entry.get("id", f"entry {index}")
        for field in REQUIRED_TEXT_FIELDS:
            value = entry.get(field)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{advisory_id} has a missing or empty {field}")
        if not isinstance(advisory_id, str) or not RUSTSEC.fullmatch(advisory_id):
            errors.append(f"entry {index} has an invalid RustSec advisory ID")
        try:
            expiry = date.fromisoformat(entry["expires"])
        except (KeyError, TypeError, ValueError):
            errors.append(f"{advisory_id} has an invalid expiry date")
            continue
        expiries.append(expiry)
        if expiry <= today:
            errors.append(f"{advisory_id} expired on {expiry.isoformat()}")

    if errors:
        print("Security exception validation failed:", *errors, sep="\n- ")
        return 1

    print(
        f"Validated {len(ids)} synchronized RustSec exceptions; "
        f"next expiry: {min(expiries).isoformat()}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
