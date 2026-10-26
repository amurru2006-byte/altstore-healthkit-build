# SPDX-License-Identifier: AGPL-3.0-only
import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("adaptation", ROOT / "scripts/apply_healthkit.py")
adaptation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adaptation)
PRIVACY_SPEC = importlib.util.spec_from_file_location("privacy", ROOT / "scripts/privacy_gate.py")
privacy = importlib.util.module_from_spec(PRIVACY_SPEC)
PRIVACY_SPEC.loader.exec_module(privacy)
PACKAGE_SPEC = importlib.util.spec_from_file_location("package", ROOT / "scripts/package.py")
package = importlib.util.module_from_spec(PACKAGE_SPEC)
PACKAGE_SPEC.loader.exec_module(package)
sys.path.insert(0, str(ROOT / "scripts"))
import test_auth_refresh
import test_auth_identity


class PatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.header = (ROOT / "tests/fixtures/ALTCapabilities.h").read_text()
        cls.source = (ROOT / "tests/fixtures/ALTCapabilities.m").read_text()
        cls.config = json.loads((ROOT / "upstream.json").read_text())
        cls.auth = "synthetic original prefix\n" + adaptation.AUTH_ANCHOR + "\nsynthetic original suffix\n"
        cls.anisette_fetch = "synthetic original prefix\n" + adaptation.IDENTITY_ANCHOR + "\nsynthetic original suffix\n"
        cls.anisette_fetch_pin = adaptation.source_blob_sha1(cls.anisette_fetch)

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

    def test_arm64_verification_places_input_before_architecture_list(self):
        executable = Path("synthetic/AltStore.app/AltStore")
        with mock.patch.object(package.subprocess, "run") as run:
            package.verify_arm64(executable)
        run.assert_called_once_with(
            ["xcrun", "lipo", str(executable), "-verify_arch", "arm64"], check=True
        )

    def test_refresh_patch_preserves_every_existing_byte_outside_insertion(self):
        patched = adaptation.patch_authentication(self.auth)
        self.assertEqual(patched.replace(adaptation.REFRESH_BLOCK, "", 1), self.auth)
        self.assertEqual(patched.count("anisetteDataRefreshHandler ="), 1)
        self.assertLess(patched.index("anisetteDataRefreshHandler"), patched.index(adaptation.AUTH_ANCHOR))

    def test_refresh_patch_rejects_duplicate_application(self):
        patched = adaptation.patch_authentication(self.auth)
        with self.assertRaises(ValueError):
            adaptation.patch_authentication(patched)

    def test_refresh_patch_rejects_missing_or_ambiguous_anchor(self):
        for source in ("synthetic unrelated source", self.auth + adaptation.AUTH_ANCHOR):
            with self.subTest(source=source):
                with self.assertRaises(ValueError):
                    adaptation.patch_authentication(source)

    def test_refresh_closure_uses_existing_fetch_and_checks_owner_lifetime(self):
        block = adaptation.REFRESH_BLOCK
        self.assertIn("FetchAnisetteDataOperation(context: self.context)", block)
        self.assertEqual(block.count("[weak self]"), 2)
        self.assertEqual(block.count("!self.isCancelled, !self.isFinished"), 2)
        self.assertIn("case .failure(let error): completionHandler(nil, error)", block)
        self.assertIn("case .success(let anisetteData): completionHandler(anisetteData, nil)", block)

    def test_native_harness_extracts_exact_production_body(self):
        patched = adaptation.patch_authentication(self.auth)
        body = test_auth_refresh.extract_refresh_block(patched)
        self.assertIn("anisetteDataRefreshHandler =", body)
        self.assertIn(body, adaptation.REFRESH_BLOCK)
        for invalid in (self.auth, patched + adaptation.REFRESH_BEGIN, patched + adaptation.REFRESH_END):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    test_auth_refresh.extract_refresh_block(invalid)

    def test_identity_patch_preserves_every_existing_byte_outside_insertion(self):
        patched = adaptation.patch_anisette_identity(self.anisette_fetch, self.anisette_fetch_pin)
        self.assertEqual(patched.replace("\n" + adaptation.IDENTITY_BLOCK, "", 1), self.anisette_fetch)
        self.assertEqual(patched.count("authenticationUserAgent = response.userAgent"), 1)
        self.assertIn(adaptation.IDENTITY_ANCHOR + "\n" + adaptation.IDENTITY_BLOCK, patched)

    def test_identity_patch_rejects_repeat_application(self):
        patched = adaptation.patch_anisette_identity(self.anisette_fetch, self.anisette_fetch_pin)
        with self.assertRaises(ValueError):
            adaptation.patch_anisette_identity(patched, self.anisette_fetch_pin)

    def test_identity_patch_rejects_mutation_or_incorrect_pin(self):
        for source, expected_pin in (
            (self.anisette_fetch + "synthetic mutation", self.anisette_fetch_pin),
            (self.anisette_fetch, "0" * 40),
            (self.anisette_fetch, ""),
        ):
            with self.subTest(source=source, pin=expected_pin):
                with self.assertRaises(ValueError):
                    adaptation.patch_anisette_identity(source, expected_pin)

    def test_identity_patch_rejects_absent_or_ambiguous_anchor_even_with_matching_pin(self):
        for source in ("synthetic unrelated source", self.anisette_fetch + adaptation.IDENTITY_ANCHOR):
            with self.subTest(source=source):
                with self.assertRaises(ValueError):
                    adaptation.patch_anisette_identity(source, adaptation.source_blob_sha1(source))

    def test_identity_baseline_requires_reviewed_unmodified_source(self):
        test_auth_identity.verify_baseline(self.anisette_fetch, self.anisette_fetch_pin)
        patched = adaptation.patch_anisette_identity(self.anisette_fetch, self.anisette_fetch_pin)
        for source, pin in (
            (self.anisette_fetch + "synthetic mutation", self.anisette_fetch_pin),
            (patched, adaptation.source_blob_sha1(patched)),
            ("synthetic unrelated source", adaptation.source_blob_sha1("synthetic unrelated source")),
        ):
            with self.subTest(source=source):
                with self.assertRaises(ValueError):
                    test_auth_identity.verify_baseline(source, pin)

    def test_identity_native_harness_extracts_exact_success_path(self):
        patched = adaptation.patch_anisette_identity(self.anisette_fetch, self.anisette_fetch_pin)
        path = test_auth_identity.extract_identity_path(patched)
        self.assertIn(path, patched)
        self.assertEqual(path, adaptation.IDENTITY_ANCHOR + "\n" + adaptation.IDENTITY_BLOCK)
        self.assertEqual(test_auth_identity.EXPECTED_CHECKS, 16)
        self.assertLess(path.index("try await self.fetchHeaders"), path.index("authenticationUserAgent ="))

    def test_identity_native_harness_rejects_absent_duplicate_moved_or_reversed_markers(self):
        patched = adaptation.patch_anisette_identity(self.anisette_fetch, self.anisette_fetch_pin)
        reversed_markers = (adaptation.IDENTITY_END + "\n" + adaptation.IDENTITY_ANCHOR + "\n" +
                            adaptation.IDENTITY_BEGIN + "\nsynthetic assignment")
        for source in (
            self.anisette_fetch,
            patched + adaptation.IDENTITY_BEGIN,
            patched + adaptation.IDENTITY_END,
            patched.replace(adaptation.IDENTITY_ANCHOR + "\n", adaptation.IDENTITY_ANCHOR + "\nsynthetic gap\n"),
            reversed_markers,
        ):
            with self.subTest(source=source):
                with self.assertRaises(ValueError):
                    test_auth_identity.extract_identity_path(source)

    def test_hk4_has_newer_build_and_pinned_authentication_sources(self):
        self.assertEqual(self.config["build"], "7003")
        self.assertEqual(self.config["candidate_tag"], "hk4")
        self.assertRegex(self.config["authentication_blob_sha1"], r"^[a-f0-9]{40}$")
        self.assertEqual(self.config["anisette_fetch_blob_sha1"], "8d84fc17604b3f3d9f5b53331090cfa79721413a")
        workflow = (ROOT / ".github/workflows/build.yml").read_text()
        self.assertIn("CURRENT_PROJECT_VERSION=7003", workflow)
        self.assertIn("Refresh checks: 18; failures: 0", workflow)
        self.assertIn("Authentication identity checks: 16; failures: 0", workflow)
        self.assertIn("build/DerivedData/SourcePackages/checkouts", workflow)


if __name__ == "__main__":
    unittest.main()
