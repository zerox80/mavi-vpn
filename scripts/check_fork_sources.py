#!/usr/bin/env python3
"""Validate branch tracking and optionally require current zerox80 fork heads."""

from __future__ import annotations

import argparse
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CARGO_TOML = ROOT / "Cargo.toml"
CARGO_LOCK = ROOT / "Cargo.lock"


@dataclass(frozen=True)
class Fork:
    repository: str
    branch: str


EXPECTED = {
    "h2": Fork("https://github.com/zerox80/h2", "master"),
    "h3": Fork("https://github.com/zerox80/h3", "main"),
    "h3-datagram": Fork("https://github.com/zerox80/h3", "main"),
    "h3-quinn": Fork("https://github.com/zerox80/h3", "main"),
    "quinn": Fork("https://github.com/zerox80/quinn", "main"),
    "quinn-proto": Fork("https://github.com/zerox80/quinn", "main"),
    "quinn-udp": Fork("https://github.com/zerox80/quinn", "main"),
}


def load_toml(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def validate_manifest(errors: list[str]) -> None:
    patches = load_toml(CARGO_TOML).get("patch", {}).get("crates-io", {})
    for package, expected in EXPECTED.items():
        dependency = patches.get(package)
        if not isinstance(dependency, dict):
            errors.append(f"Cargo.toml patch for {package} is missing or is not a table")
            continue
        if dependency.get("git") != expected.repository:
            errors.append(f"Cargo.toml patch for {package} must use {expected.repository}")
        if dependency.get("branch") != expected.branch:
            errors.append(f"Cargo.toml patch for {package} must track branch {expected.branch}")
        for forbidden in ("rev", "tag"):
            if forbidden in dependency:
                errors.append(f"Cargo.toml patch for {package} must never set {forbidden}")


def validate_lock(errors: list[str]) -> dict[Fork, str]:
    packages = load_toml(CARGO_LOCK).get("package", [])
    commits_by_fork: dict[Fork, set[str]] = {}

    for package, expected in EXPECTED.items():
        matches = [entry for entry in packages if entry.get("name") == package]
        if len(matches) != 1:
            errors.append(
                f"Cargo.lock must contain exactly one {package} package; "
                f"found {len(matches)}"
            )
            continue
        source = matches[0].get("source", "")
        prefix = f"git+{expected.repository}?branch={expected.branch}#"
        if not source.startswith(prefix):
            errors.append(f"Cargo.lock {package} must resolve from {prefix}<commit>")
            continue
        commit = source.removeprefix(prefix)
        if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
            errors.append(f"Cargo.lock {package} has an invalid Git commit: {commit}")
            continue
        commits_by_fork.setdefault(expected, set()).add(commit)

    resolved: dict[Fork, str] = {}
    for fork, commits in commits_by_fork.items():
        if len(commits) != 1:
            errors.append(
                f"Cargo.lock packages from {fork.repository} disagree on commits: "
                f"{sorted(commits)}"
            )
        else:
            resolved[fork] = next(iter(commits))
    return resolved


def remote_head(fork: Fork) -> str:
    process = subprocess.run(
        ["git", "ls-remote", fork.repository, f"refs/heads/{fork.branch}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    fields = process.stdout.strip().split()
    if len(fields) != 2:
        raise ValueError(f"unexpected ls-remote output for {fork.repository} {fork.branch}")
    return fields[0]


def validate_remote_heads(resolved: dict[Fork, str], errors: list[str]) -> None:
    for fork in sorted(set(EXPECTED.values()), key=lambda item: item.repository):
        locked = resolved.get(fork)
        if locked is None:
            continue
        try:
            latest = remote_head(fork)
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            errors.append(f"Could not read {fork.repository} {fork.branch}: {error}")
            continue
        if locked != latest:
            errors.append(
                f"Cargo.lock is stale for {fork.repository} {fork.branch}: "
                f"locked {locked}, latest {latest}"
            )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check-remote",
        action="store_true",
        help="also require Cargo.lock commits to equal the current remote branch heads",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    errors: list[str] = []
    try:
        validate_manifest(errors)
        resolved = validate_lock(errors)
    except (OSError, tomllib.TOMLDecodeError) as error:
        errors.append(str(error))
        resolved = {}

    if args.check_remote:
        validate_remote_heads(resolved, errors)

    if errors:
        print("Fork source validation failed:", *errors, sep="\n- ")
        return 1

    mode = " and remote heads" if args.check_remote else ""
    print(f"Validated {len(EXPECTED)} branch-tracked fork packages{mode}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
