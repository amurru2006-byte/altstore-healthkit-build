# SPDX-License-Identifier: AGPL-3.0-only
"""Compile the exact provider-fetch/identity-assignment path with synthetic doubles."""
import argparse
import json
import subprocess
from pathlib import Path

from apply_healthkit import IDENTITY_ANCHOR, IDENTITY_BEGIN, IDENTITY_END, source_blob_sha1

ROOT = Path(__file__).parents[1]
EXPECTED_CHECKS = 16


def verify_baseline(source, expected_blob_sha1):
    if "authenticationUserAgent" in source:
        raise ValueError("Baseline already wires authentication identity; review instead of patching")
    if source_blob_sha1(source) != expected_blob_sha1:
        raise ValueError("Anisette fetch baseline differs from reviewed pinned blob")
    if source.count(IDENTITY_ANCHOR) != 1:
        raise ValueError("Expected one reviewed provider-fetch anchor")


def extract_identity_path(source):
    if source.count(IDENTITY_BEGIN) != 1 or source.count(IDENTITY_END) != 1:
        raise ValueError("Expected exactly one production authentication identity block")
    start = IDENTITY_ANCHOR + "\n" + IDENTITY_BEGIN
    if source.count(start) != 1:
        raise ValueError("Identity assignment must immediately follow the successful provider fetch")
    start_index = source.index(start)
    end_index = source.index(IDENTITY_END)
    if end_index <= start_index:
        raise ValueError("Authentication identity markers are out of order")
    return source[start_index:end_index + len(IDENTITY_END)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("--expect-missing", action="store_true")
    args = parser.parse_args()
    source = (args.source / "AltStore/Operations/FetchAnisetteDataOperation.swift").read_text()
    if args.expect_missing:
        config = json.loads((ROOT / "upstream.json").read_text())
        verify_baseline(source, config["anisette_fetch_blob_sha1"])
        print("Pinned iPhone baseline has no authentication identity assignment")
        return
    path = extract_identity_path(source)
    template = (ROOT / "tests/AuthenticationIdentityHarness.swift").read_text()
    marker = "// INJECT_PRODUCTION_AUTHENTICATION_IDENTITY_PATH"
    if template.count(marker) != 1:
        raise SystemExit("Unexpected native identity harness template")
    build = ROOT / "build"
    build.mkdir(exist_ok=True)
    harness = build / "AuthenticationIdentityHarness.swift"
    binary = build / "authentication-identity-tests"
    harness.write_text(template.replace(marker, path))
    subprocess.run(["xcrun", "swiftc", "-parse-as-library", str(harness), "-o", str(binary)], check=True)
    result = subprocess.run([str(binary)], check=True, text=True, capture_output=True)
    print(result.stdout, end="")
    expected = f"Authentication identity checks: {EXPECTED_CHECKS}; failures: 0"
    if result.stdout.splitlines() != [expected]:
        raise SystemExit("Unexpected native authentication identity check count or output")


if __name__ == "__main__":
    main()
