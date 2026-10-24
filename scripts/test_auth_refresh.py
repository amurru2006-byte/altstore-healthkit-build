# SPDX-License-Identifier: AGPL-3.0-only
"""Compile the exact injected production closure against synthetic native doubles."""
import argparse
import subprocess
from pathlib import Path

from apply_healthkit import REFRESH_BEGIN, REFRESH_END

ROOT = Path(__file__).parents[1]


def extract_refresh_block(source):
    if source.count(REFRESH_BEGIN) != 1 or source.count(REFRESH_END) != 1:
        raise ValueError("Expected exactly one production refresh block")
    return source.split(REFRESH_BEGIN, 1)[1].split(REFRESH_END, 1)[0]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("--expect-missing", action="store_true")
    args = parser.parse_args()
    source = (args.source / "AltStore/Operations/AuthenticationOperation.swift").read_text()
    if args.expect_missing:
        if "anisetteDataRefreshHandler" in source:
            raise SystemExit("Baseline already wires refresh; review instead of patching")
        print("Pinned iPhone baseline has no refresh handler")
        return
    block = extract_refresh_block(source)
    template = (ROOT / "tests/RefreshHandlerHarness.swift").read_text()
    if template.count("// INJECT_PRODUCTION_REFRESH_BLOCK") != 1:
        raise SystemExit("Unexpected native harness template")
    build = ROOT / "build"
    build.mkdir(exist_ok=True)
    harness = build / "RefreshHandlerHarness.swift"
    binary = build / "refresh-handler-tests"
    harness.write_text(template.replace("// INJECT_PRODUCTION_REFRESH_BLOCK", block))
    subprocess.run(["xcrun", "swiftc", str(harness), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    main()
