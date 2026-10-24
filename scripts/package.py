# SPDX-License-Identifier: AGPL-3.0-only
"""Inspect and package the unsigned/ad-hoc build; never load developer credentials."""
import hashlib
import json
import os
import plistlib
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).parents[1]


def verify_arm64(executable):
    # lipo consumes all arguments after -verify_arch as architecture names.
    subprocess.run(["xcrun", "lipo", str(executable), "-verify_arch", "arm64"], check=True)


def main():
    config = json.loads((ROOT / "upstream.json").read_text())
    app = ROOT / "build/DerivedData/Build/Products/Release-iphoneos/AltStore.app"
    info = plistlib.loads((app / "Info.plist").read_bytes())
    required = {
        "CFBundleIdentifier": config["bundle_identifier"],
        "CFBundleDisplayName": config["display_name"],
        "CFBundleShortVersionString": config["version"],
        "CFBundleVersion": config["build"],
        "ALTVersion": config["version"],
    }
    if any(info.get(key) != value for key, value in required.items()):
        raise SystemExit("App identity/version does not match reviewed configuration")
    if set(info) & {"ALTDeviceID", "ALTServerID", "ALTCertificateID"}:
        raise SystemExit("Device/server/certificate identity must not be embedded in public builds")
    executables = []
    widgets = list((app / "PlugIns").glob("*.appex"))
    if len(widgets) != 1:
        raise SystemExit("Expected the original single widget extension")
    for bundle in [app, *widgets, *app.rglob("*.framework")]:
        bundle_info = plistlib.loads((bundle / "Info.plist").read_bytes())
        executable = bundle / bundle_info["CFBundleExecutable"]
        verify_arm64(executable)
        executables.append(executable)
    if not any(b"HK421J6T7P" in path.read_bytes() for path in executables):
        raise SystemExit("Compiled application does not contain the HealthKit feature mapping")
    subprocess.run(["codesign", "--verify", "--deep", "--strict", str(app)], check=True)
    output = ROOT / "build/output"
    output.mkdir(parents=True, exist_ok=False)
    ipa = output / "AltStore-2.3.1-HealthKit-hk2.ipa"
    for path in app.rglob("*"):
        if path.is_file() and path.suffix.lower() in {".p12", ".pfx", ".key", ".mobileprovision", ".devicepairing"}:
            raise SystemExit("Credential/provisioning files must not enter public package")
    with zipfile.ZipFile(ipa, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(app.rglob("*")):
            if path.is_symlink():
                raise SystemExit("Unexpected symlink in built app; review packaging")
            if path.is_file():
                archive.write(path, "Payload/AltStore.app/" + path.relative_to(app).as_posix())
    with zipfile.ZipFile(ipa) as archive:
        if archive.testzip() is not None:
            raise SystemExit("IPA CRC verification failed")
    manifest = {
        **config,
        "adaptation_commit": os.environ.get("GITHUB_SHA", "LOCAL_SYNTHETIC_BUILD"),
        "sha256": hashlib.sha256(ipa.read_bytes()).hexdigest(),
        "bytes": ipa.stat().st_size,
        "native_capability_checks": 14,
        "signing": "ad-hoc; must be re-signed on the owner's device",
        "device_identity_embedded": False,
        "real_device_healthkit_verified": False,
        "provider_login_verified_by_build": False,
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
