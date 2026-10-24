# SPDX-License-Identifier: AGPL-3.0-only
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("adaptation", ROOT / "scripts/apply_healthkit.py")
adaptation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adaptation)
PRIVACY_SPEC = importlib.util.spec_from_file_location("privacy", ROOT / "scripts/privacy_gate.py")
privacy = importlib.util.module_from_spec(PRIVACY_SPEC)
PRIVACY_SPEC.loader.exec_module(privacy)


class PatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.header = (ROOT / "tests/fixtures/ALTCapabilities.h").read_text()
        cls.source = (ROOT / "tests/fixtures/ALTCapabilities.m").read_text()
        cls.config = json.loads((ROOT / "upstream.json").read_text())

    def test_maps_only_base_boolean_healthkit(self):
        header, source = adaptation.patch_capabilities(self.header, self.source)
        self.assertIn("extern ALTEntitlement const ALTEntitlementHealthKit;", header)
        self.assertIn('@"com.apple.developer.healthkit"', source)
        self.assertIn('@"HK421J6T7P"', source)
        self.assertNotIn("healthkit.access", source)
        self.assertNotIn("healthkit.background-delivery", source)

    def test_existing_legacy_registration_is_unchanged(self):
        _, patched = adaptation.patch_capabilities(self.header, self.source)
        self.assertEqual(self.source.split("BOOL ALTFeatureIsLegacy", 1)[1],
                         patched.split("BOOL ALTFeatureIsLegacy", 1)[1])

    def test_refuses_repeat_application(self):
        header, source = adaptation.patch_capabilities(self.header, self.source)
        with self.assertRaises(ValueError):
            adaptation.patch_capabilities(header, source)

    def test_refuses_missing_or_ambiguous_anchor(self):
        anchor = "extern ALTFeature const ALTFeatureInterAppAudio;"
        for header in (self.header.replace(anchor, ""), self.header + anchor):
            with self.subTest(header=header):
                with self.assertRaises(ValueError):
                    adaptation.patch_capabilities(header, self.source)

    def test_removes_device_server_certificate_metadata(self):
        info = {"ALTDeviceID": "SYNTHETIC_DEVICE", "ALTServerID": "SYNTHETIC_SERVER",
                "ALTCertificateID": "SYNTHETIC_CERTIFICATE", "CFBundleIdentifier": "$(PRODUCT_BUNDLE_IDENTIFIER)"}
        result = adaptation.sanitize_info(info, self.config)
        self.assertFalse(set(result) & {"ALTDeviceID", "ALTServerID", "ALTCertificateID"})
        self.assertEqual(result["CFBundleIdentifier"], info["CFBundleIdentifier"])
        self.assertEqual(result["ALTVersion"], "2.3.1")
        self.assertEqual(result["CFBundleDisplayName"], "AltStore HK Test")
        self.assertEqual(info["ALTDeviceID"], "SYNTHETIC_DEVICE")

    def test_metadata_is_repeatable(self):
        first = adaptation.sanitize_info({}, self.config)
        self.assertEqual(first, adaptation.sanitize_info(first, self.config))

    def test_preserves_original_bundle_identity_and_increases_build(self):
        self.assertEqual(self.config["bundle_identifier"], "com.rileytestut.AltStore")
        self.assertGreater(int(self.config["build"]), 6501)
        for key in ("altstore_commit", "altsign_commit"):
            self.assertRegex(self.config[key], r"^[a-f0-9]{40}$")

    def test_commit_metadata_rejects_personal_or_unknown_addresses(self):
        privacy.validate_author_addresses(["automation" + "@" + "users.noreply.github.com"])
        for address in ("", "SYNTHETIC_INVALID_ADDRESS", "person" + "@" + "example.invalid"):
            with self.subTest(address=address):
                with self.assertRaises(ValueError):
                    privacy.validate_author_addresses([address])

    def test_workflow_disallows_private_runners_and_checks_full_history(self):
        workflow = (ROOT / ".github/workflows/build.yml").read_text()
        self.assertEqual(workflow.count("if: ${{ github.event.repository.private == false }}"), 2)
        self.assertEqual(workflow.count("fetch-depth: 0"), 2)


if __name__ == "__main__":
    unittest.main()
