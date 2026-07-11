#!/usr/bin/env python3
"""Fail CI when RustSec exceptions drift or outlive their review window."""

from __future__ import annotations

from datetime import date
from pathlib import Path
import re
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[1]
EXCEPTIONS = ROOT / "security-exceptions.toml"
DENY = ROOT / "deny.toml"
RUSTSEC = re.compile(r'"(RUSTSEC-\d{4}-\d{4})"')


def main() -> int:
    data = tomllib.loads(EXCEPTIONS.read_text(encoding="utf-8"))
    entries = data.get("exception", [])
    ids = [entry["id"] for entry in entries]
    deny_ids = RUSTSEC.findall(DENY.read_text(encoding="utf-8"))
    errors: list[str] = []

    if len(ids) != len(set(ids)):
        errors.append("security-exceptions.toml contains duplicate advisory IDs")
    if set(ids) != set(deny_ids):
        errors.append("security-exceptions.toml and deny.toml must list the same advisory IDs")

    today = date.today()
    for entry in entries:
        try:
            expiry = date.fromisoformat(entry["expires"])
        except (KeyError, TypeError, ValueError):
            errors.append(f"{entry.get('id', '<unknown>')} has an invalid expiry date")
            continue
        if expiry <= today:
            errors.append(f"{entry['id']} expired on {expiry.isoformat()}")

    if errors:
        print("Security exception validation failed:", *errors, sep="\n- ")
        return 1
    print(f"Validated {len(ids)} RustSec exceptions; next expiry: {min(entry['expires'] for entry in entries)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
