# SPDX-License-Identifier: MIT
"""Fail-closed, diagnostic-only public-source transformation. No user inputs."""
import argparse
import hashlib
import json
import subprocess
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONFIG = json.loads((HERE / "upstream.json").read_text(encoding="utf-8"))
MODULE_PATH = "src-tauri/src/network_diagnostics.rs"
LOG_FILTER = 'tracing_subscriber::filter::filter_fn(|metadata| metadata.target() == "pivot_network_diagnostics")'
BANNER = '''      <aside role="note" style={{ padding: "12px", border: "2px solid #d59a36" }}>
        UNOFFICIAL diagnostic D2 — network categories only; not an official iloader release.
        {" "}<a href="https://iloader.app" target="_blank" rel="noreferrer">Official upstream: iloader.app</a>
      </aside>
'''
ERROR_INSERT = '''        let report_str = if let Some(summary) = crate::network_diagnostics::summarize_report(&report) {
            tracing::error!(target: "pivot_network_diagnostics", diagnostics = summary.as_str(), "Sanitized network diagnostics");
            summary
        } else {
            report.to_string()
        };'''


def git(*args, cwd):
    return subprocess.check_output(["git", "-c", "credential.helper=", *args], cwd=cwd, text=True).strip()


def blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def once(source, before, after, count=1):
    if source.count(before) != count:
        raise ValueError("Missing, repeated or ambiguous diagnostic anchor")
    return source.replace(before, after)


def package_graph(lock):
    packages = tomllib.loads(lock)["package"]
    # The root gets one direct edge to an already-locked package, nothing else.
    result = []
    for package in packages:
        value = dict(package)
        if value["name"] == "iloader":
            value["dependencies"] = [d for d in value["dependencies"] if d != "reqwest-middleware"]
        result.append(value)
    return result


def transform(original):
    output = dict(original)
    key = "src-tauri/src/error.rs"
    output[key] = once(output[key], "        let report_str = report.to_string();", ERROR_INSERT)
    key = "src-tauri/src/lib.rs"
    output[key] = once(output[key], "mod logging;", "mod logging;\nmod network_diagnostics;")
    output[key] = once(output[key], "tracing_subscriber::filter::LevelFilter::DEBUG", LOG_FILTER, 2)
    key = "src-tauri/Cargo.toml"
    output[key] = once(output[key], 'reqwest = "0.13.2"', 'reqwest = "0.13.2"\nreqwest-middleware = "=0.5.2"')
    key = "src-tauri/Cargo.lock"
    start = output[key].index('name = "iloader"\n')
    end = output[key].index("\n[[package]]", start)
    root = output[key][start:end]
    root = once(root, ' "reqwest",\n', ' "reqwest",\n "reqwest-middleware",\n')
    output[key] = output[key][:start] + root + output[key][end:]
    if package_graph(output[key]) != package_graph(original[key]):
        raise ValueError("Locked dependency graph changed")
    key = "src-tauri/tauri.conf.json"
    output[key] = once(output[key], '"title": "iloader"', '"title": "iloader — UNOFFICIAL Diagnostic D2"')
    key = "src/App.tsx"
    output[key] = once(output[key], "      </header>\n", "      </header>\n" + BANNER)
    return output


def verify_protected(root):
    if git("rev-parse", "HEAD", cwd=root) != CONFIG["commit"]:
        raise ValueError("Upstream commit mismatch")
    for relative, expected in CONFIG["protected_blobs"].items():
        if blob((root / relative).read_bytes()) != expected:
            raise ValueError(f"Protected source changed: {relative}")
    manifest = tomllib.loads((root / "src-tauri/Cargo.lock").read_text(encoding="utf-8"))
    package = next(p for p in manifest["package"] if p["name"] == "isideload")
    if package["version"] != "0.5.0" or package["checksum"] != "649ccce64715f7b8f1e9eb330defc48d06d5d35eb8d13d17783533b02c67ba32":
        raise ValueError("Authentication/signing dependency changed")


def patch(root):
    verify_protected(root)
    original = {}
    for relative, expected in CONFIG["blobs"].items():
        data = (root / relative).read_bytes()
        if blob(data) != expected:
            raise ValueError(f"Unreviewed or already-patched upstream blob: {relative}")
        original[relative] = data.decode("utf-8")
    if (root / MODULE_PATH).exists():
        raise ValueError("Diagnostic module already exists")
    result = transform(original)
    for relative, content in result.items():
        (root / relative).write_bytes(content.encode("utf-8"))
    (root / MODULE_PATH).write_bytes((HERE / "network_diagnostics.rs").read_bytes())
    verify(root)


def verify(root):
    verify_protected(root)
    original = {relative: subprocess.check_output(["git", "show", "HEAD:" + relative], cwd=root).decode("utf-8")
                for relative in CONFIG["blobs"]}
    for relative, content in transform(original).items():
        if (root / relative).read_bytes() != content.encode("utf-8"):
            raise ValueError(f"Unexpected patch surface: {relative}")
    changed = set(git("diff", "--name-only", "HEAD", cwd=root).splitlines())
    if changed != set(CONFIG["blobs"]):
        raise ValueError("Unexpected modified upstream files")
    extra = set(git("ls-files", "--others", "--exclude-standard", cwd=root).splitlines())
    if extra != {MODULE_PATH}:
        raise ValueError("Unexpected untracked upstream files")
    if (root / MODULE_PATH).read_bytes() != (HERE / "network_diagnostics.rs").read_bytes():
        raise ValueError("Compiled diagnostic module differs from reviewed source")
    print("Diagnostic patch surface and protected authentication/signing sources verified")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["fetch", "patch", "verify"])
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    if args.mode == "fetch":
        if root.exists():
            raise SystemExit("Destination exists; refusing to overwrite")
        root.mkdir(parents=True)
        git("init", cwd=root)
        git("config", "core.autocrlf", "false", cwd=root)
        git("remote", "add", "origin", CONFIG["repository"], cwd=root)
        git("fetch", "--depth=1", "origin", CONFIG["commit"], cwd=root)
        git("checkout", "--detach", "FETCH_HEAD", cwd=root)
        verify_protected(root)
    elif args.mode == "patch":
        patch(root)
    else:
        verify(root)


if __name__ == "__main__":
    main()
