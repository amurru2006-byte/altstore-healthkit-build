# SPDX-License-Identifier: AGPL-3.0-only
"""Narrow, fail-closed source adaptation. Never accepts credentials or device IDs."""
import argparse
import json
import plistlib
from pathlib import Path

AUTH_ANCHOR = "        // Apple can ask for the anisette data to be resynchronized partway through signing in (hsc 434),"
REFRESH_BEGIN = "        // HK3 refresh handler begin"
REFRESH_END = "        // HK3 refresh handler end"
REFRESH_BLOCK = '''        // HK3 refresh handler begin
        // Fetch fresh data using the existing selected transport; preserve all authentication checks.
        ALTAppleAPI.shared.anisetteDataRefreshHandler = { [weak self] completionHandler in
            guard let self, !self.isCancelled, !self.isFinished else {
                return completionHandler(nil, OperationError.cancelled)
            }

            let refreshOperation = FetchAnisetteDataOperation(context: self.context)
            refreshOperation.resultHandler = { [weak self] result in
                guard let self, !self.isCancelled, !self.isFinished else {
                    return completionHandler(nil, OperationError.cancelled)
                }
                switch result
                {
                case .failure(let error): completionHandler(nil, error)
                case .success(let anisetteData): completionHandler(anisetteData, nil)
                }
            }
            self.operationQueue.addOperation(refreshOperation)
        }
        // HK3 refresh handler end

'''


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError(f"Expected one unmodified anchor: {old!r}")
    return source.replace(old, new, 1)


def patch_capabilities(header, implementation):
    if "ALTEntitlementHealthKit" in header + implementation:
        raise ValueError("HealthKit mapping already present; review upstream before applying")
    header = replace_once(
        header,
        "extern ALTEntitlement const ALTEntitlementInterAppAudio;",
        "extern ALTEntitlement const ALTEntitlementInterAppAudio;\n"
        "extern ALTEntitlement const ALTEntitlementHealthKit;",
    )
    header = replace_once(
        header,
        "extern ALTFeature const ALTFeatureInterAppAudio;",
        "extern ALTFeature const ALTFeatureInterAppAudio;\n"
        "extern ALTFeature const ALTFeatureHealthKit;",
    )
    implementation = replace_once(
        implementation,
        'ALTEntitlement const ALTEntitlementInterAppAudio = @"inter-app-audio";',
        'ALTEntitlement const ALTEntitlementInterAppAudio = @"inter-app-audio";\n'
        'ALTEntitlement const ALTEntitlementHealthKit = @"com.apple.developer.healthkit";',
    )
    implementation = replace_once(
        implementation,
        'ALTFeature const ALTFeatureInterAppAudio = @"IAD53UNK2F";',
        'ALTFeature const ALTFeatureInterAppAudio = @"IAD53UNK2F";\n'
        'ALTFeature const ALTFeatureHealthKit = @"HK421J6T7P";',
    )
    implementation = replace_once(
        implementation,
        "else if ([feature isEqualToString:ALTFeatureIncreasedMemoryLimit])",
        "else if ([feature isEqualToString:ALTFeatureHealthKit])\n"
        "    {\n        return ALTEntitlementHealthKit;\n    }\n    "
        "else if ([feature isEqualToString:ALTFeatureIncreasedMemoryLimit])",
    )
    implementation = replace_once(
        implementation,
        "else if ([entitlement isEqualToString:ALTEntitlementIncreasedMemoryLimit])",
        "else if ([entitlement isEqualToString:ALTEntitlementHealthKit])\n"
        "    {\n        return ALTFeatureHealthKit;\n    }\n    "
        "else if ([entitlement isEqualToString:ALTEntitlementIncreasedMemoryLimit])",
    )
    return header, implementation


def sanitize_info(info, config):
    info = dict(info)
    for key in ("ALTDeviceID", "ALTServerID", "ALTCertificateID"):
        info.pop(key, None)
    info["ALTVersion"] = config["version"]
    info["CFBundleDisplayName"] = config["display_name"]
    return info


def patch_authentication(source):
    if "anisetteDataRefreshHandler" in source:
        raise ValueError("Refresh wiring already present; review upstream before applying")
    return replace_once(source, AUTH_ANCHOR, REFRESH_BLOCK + AUTH_ANCHOR)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    args = parser.parse_args()
    config = json.loads((Path(__file__).parents[1] / "upstream.json").read_text())
    directory = args.source / "Dependencies/AltSign/AltSign/Capabilities"
    header_path = directory / "ALTCapabilities.h"
    implementation_path = directory / "ALTCapabilities.m"
    info_path = args.source / "AltStore/Info.plist"
    authentication_path = args.source / "AltStore/Operations/AuthenticationOperation.swift"
    header, implementation = patch_capabilities(
        header_path.read_text(), implementation_path.read_text()
    )
    info = sanitize_info(plistlib.loads(info_path.read_bytes()), config)
    authentication = patch_authentication(authentication_path.read_text())
    # Validate every transformation before writing any source file.
    header_path.write_text(header)
    implementation_path.write_text(implementation)
    info_path.write_bytes(plistlib.dumps(info))
    authentication_path.write_text(authentication)


if __name__ == "__main__":
    main()
