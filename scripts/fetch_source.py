# SPDX-License-Identifier: AGPL-3.0-only
"""Fetch public, pinned source; no credential files or local app data are inputs."""
import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).parents[1]


def git(*args, cwd=None):
    return subprocess.check_output(
        ["git", "-c", "credential.helper=", *args], cwd=cwd, text=True, timeout=600
    ).strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    destination = args.destination.resolve()
    if destination.exists():
        raise SystemExit("Destination already exists; refusing to overwrite")
    config = json.loads((ROOT / "upstream.json").read_text())
    destination.mkdir(parents=True)
    git("init", str(destination))
    git("remote", "add", "origin", config["altstore_repository"], cwd=destination)
    git("fetch", "--depth=1", "origin", config["altstore_commit"], cwd=destination)
    git("checkout", "--detach", "FETCH_HEAD", cwd=destination)
    if git("rev-parse", "HEAD", cwd=destination) != config["altstore_commit"]:
        raise SystemExit("Upstream revision mismatch")
    git("submodule", "update", "--init", "--recursive", "--depth=1", cwd=destination)
    if git("rev-parse", "HEAD", cwd=destination / "Dependencies/AltSign") != config["altsign_commit"]:
        raise SystemExit("AltSign revision mismatch")
    for name in ("ALTCapabilities.h", "ALTCapabilities.m"):
        actual = (destination / "Dependencies/AltSign/AltSign/Capabilities" / name).read_text().strip()
        expected = (ROOT / "tests/fixtures" / name).read_text().strip()
        if actual != expected:
            raise SystemExit("Capability source differs from reviewed fixture")
    print("Pinned upstream and recursive dependencies verified")


if __name__ == "__main__":
    main()
