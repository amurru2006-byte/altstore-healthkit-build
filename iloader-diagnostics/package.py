# SPDX-License-Identifier: MIT
"""Package only a verified CI binary, public source and synthetic summaries."""
import argparse
import hashlib
import importlib.util
import json
import re
import shutil
import struct
import subprocess
import zipfile
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("diagnostic_recipe", HERE / "apply.py")
recipe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recipe)


def native_result(text):
    expected = recipe.CONFIG["native_test_count"]
    names = re.findall(r"^test network_diagnostics::tests::([a-z0-9_]+) \.\.\. ok$", text, re.M)
    expected_names = re.findall(r"#\[test\]\s+fn ([a-z0-9_]+)", (HERE / "network_diagnostics.rs").read_text(encoding="utf-8"))
    results = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;", text)
    if (len(names) != expected or len(set(names)) != expected or set(names) != set(expected_names)
            or len(expected_names) != expected or results != [(str(expected), "0", "0")]):
        raise ValueError("Native tests must pass exactly, without skips")
    return {"suite": "network_diagnostics", "passed": expected, "failed": 0, "ignored": 0,
            "scope": "synthetic only; no Apple login or device", "tests": sorted(names)}


def verify_pe(data):
    if len(data) < 1024 or data[:2] != b"MZ":
        raise ValueError("Missing Windows executable")
    offset = struct.unpack_from("<I", data, 0x3C)[0]
    if offset + 184 > len(data) or data[offset:offset + 4] != b"PE\0\0":
        raise ValueError("Invalid PE structure")
    if struct.unpack_from("<H", data, offset + 4)[0] != 0x8664:
        raise ValueError("Executable must be AMD64")
    if struct.unpack_from("<H", data, offset + 24)[0] != 0x20B:
        raise ValueError("Executable must be PE32+")
    if struct.unpack_from("<II", data, offset + 24 + 112 + 4 * 8) != (0, 0):
        raise ValueError("Unexpected Authenticode certificate table")
    if b"PIVOT-NET-D1" not in data:
        raise ValueError("Compiled diagnostic marker missing")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cargo_metadata(root):
    raw = subprocess.check_output(
        ["cargo", "metadata", "--locked", "--format-version=1", "--manifest-path", str(root / "src-tauri/Cargo.toml")],
        cwd=root)
    # Cargo JSON is UTF-8, not the Windows console's legacy code page.
    return json.loads(raw.decode("utf-8"))


def zip_entry(archive, name, data):
    if PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts or "\\" in name or ":" in name:
        raise ValueError("Unsafe archive entry")
    data = data.encode("utf-8") if isinstance(data, str) else data
    if name in archive.namelist():
        if archive.read(name) != data:
            raise ValueError("Conflicting duplicate archive entry")
        return
    # Registry license files may carry epoch timestamps, outside ZIP's range.
    # Normalize archive metadata only; preserve the exact public file bytes.
    entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    entry.compress_type = zipfile.ZIP_DEFLATED
    entry.external_attr = 0o100644 << 16
    archive.writestr(entry, data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("native_log", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    root, output = args.root.resolve(), args.output.resolve()
    recipe.verify(root)
    result = native_result(args.native_log.read_text(encoding="utf-8-sig"))
    binary = root / "src-tauri/target/release/iloader.exe"
    verify_pe(binary.read_bytes())
    if output.exists():
        raise SystemExit("Output exists; refusing to replace an archive")
    output.mkdir(parents=True)
    name = "iloader-2.4.0-UNOFFICIAL-diagnostic-D1-windows-x64.exe"
    shutil.copy2(binary, output / name)
    (output / "synthetic-tests.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    for license_name in ("LICENSE", "LICENSE-BRANDING"):
        shutil.copy2(root / license_name, output / license_name)
    shutil.copy2(HERE / "README.md", output / "READ-ME-FIRST.md")

    # Tracked public upstream only: never registry caches, app data, .git or logs.
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0")
    with zipfile.ZipFile(output / "Corresponding-Source.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        for relative in sorted(p for p in tracked if p):
            if Path(relative).is_absolute() or ".." in Path(relative).parts:
                raise ValueError("Unsafe public source path")
            path = root / relative
            if path.is_symlink() or not path.is_file():
                raise ValueError("Unsupported public source entry")
            zip_entry(archive, "upstream/" + relative, path.read_bytes())
        zip_entry(archive, "upstream/" + recipe.MODULE_PATH, (root / recipe.MODULE_PATH).read_bytes())
        for relative in ("README.md", "apply.py", "package.py", "upstream.json", "network_diagnostics.rs", "test_recipe.py"):
            zip_entry(archive, "diagnostic-recipe/" + relative, (HERE / relative).read_bytes())

    # Dependency manifests and public license notices, without machine paths.
    metadata = cargo_metadata(root)
    with zipfile.ZipFile(output / "Dependency-Notices.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        notices = []
        for package in metadata["packages"]:
            if package["name"] == "iloader" and package["version"] == recipe.CONFIG["version"]:
                continue
            label = package["name"] + "-" + package["version"]
            notices.append({"package": label, "license": package.get("license"), "source": package.get("source")})
            directory = Path(package["manifest_path"]).parent
            for path in sorted(directory.iterdir()):
                if path.is_file() and path.name.lower().startswith(("license", "licence", "copying", "notice")):
                    zip_entry(archive, label + "/" + path.name, path.read_bytes())
        zip_entry(archive, "rust-dependencies.json", json.dumps(notices, indent=2) + "\n")
        # The frozen Bun lock is also preserved in Corresponding-Source.zip.
        for manifest in sorted((root / "node_modules").glob("**/package.json")):
            if manifest.is_symlink():
                continue
            package = json.loads(manifest.read_text(encoding="utf-8"))
            label = str(package.get("name", "unknown")).replace("/", "_") + "-" + str(package.get("version", "unknown"))
            zip_entry(archive, "frontend/" + label + "/package.json", manifest.read_bytes())
            for path in manifest.parent.iterdir():
                if path.is_file() and path.name.lower().startswith(("license", "licence", "copying", "notice")):
                    zip_entry(archive, "frontend/" + label + "/" + path.name, path.read_bytes())

    manifest = {"upstream_commit": recipe.CONFIG["commit"], "version": recipe.CONFIG["version"],
                "diagnostic_revision": "D1", "unofficial": True, "authenticode_signed": False,
                "phone_tested": False, "apple_authentication_tested": False,
                "recipe_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=HERE, text=True).strip(),
                "native_tests": result, "files": {}}
    for path in sorted(output.iterdir()):
        manifest["files"][path.name] = {"bytes": path.stat().st_size, "sha256": digest(path)}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print("Verified unsigned AMD64 diagnostic candidate; public source/licenses and synthetic summaries only")


if __name__ == "__main__":
    main()
