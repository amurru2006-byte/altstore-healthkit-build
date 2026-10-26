# SPDX-License-Identifier: AGPL-3.0-only
"""Check only this adaptation's public source, not user directories or credentials."""
import argparse
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).parents[1]
ALLOWED = {
    ".gitattributes", ".gitignore", "README.md", "upstream.json", ".github/workflows/build.yml",
    "scripts/apply_healthkit.py", "scripts/fetch_source.py", "scripts/privacy_gate.py",
    "scripts/package.py", "tests/test_patch.py", "tests/HealthKitCapabilityTests.m",
    "tests/fixtures/ALTCapabilities.h", "tests/fixtures/ALTCapabilities.m",
    "scripts/test_auth_refresh.py", "tests/RefreshHandlerHarness.swift",
    "scripts/test_auth_identity.py", "tests/AuthenticationIdentityHarness.swift",
}
PATTERNS = (
    re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{16}\b"),
    re.compile(r"\b(?:gsk_|ghp_|github_pat_)[A-Za-z0-9_]{20,}"),
    re.compile(r"-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----"),
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
)


def validate_author_addresses(addresses):
    for address in addresses:
        if not address or not address.endswith("@users.noreply.github.com"):
            raise ValueError("Commit metadata must use a GitHub no-reply identity")


def validate_revision_paths(paths):
    if set(paths) != ALLOWED:
        raise ValueError("Revision tree must match the exact public-source allowlist")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--revision", default="HEAD")
    args = parser.parse_args()
    paths = subprocess.check_output(
        ["git", "ls-tree", "-r", "--name-only", args.revision], cwd=ROOT, text=True
    ).splitlines()
    validate_revision_paths(paths)
    for relative in sorted(ALLOWED):
        path = ROOT / relative
        if not path.is_file():
            raise SystemExit(f"Missing allowlisted source: {relative}")
        text = path.read_text(encoding="utf-8")
        if any(pattern.search(text) for pattern in PATTERNS):
            raise SystemExit(f"Sensitive-looking data in {relative}; do not publish")
        committed = subprocess.check_output(
            ["git", "show", args.revision + ":" + relative], cwd=ROOT
        ).decode("utf-8")
        if committed != text:
            raise SystemExit(f"Local and reviewed revision differ: {relative}; do not publish")
    metadata = subprocess.check_output(
        ["git", "log", "--format=%ae%x00%ce", args.revision, "--"], cwd=ROOT, text=True
    )
    addresses = [part for line in metadata.splitlines() for part in line.split("\0")]
    validate_author_addresses(addresses)
    print(f"Privacy allowlist: {len(ALLOWED)} source files and commit metadata passed")


if __name__ == "__main__":
    main()
