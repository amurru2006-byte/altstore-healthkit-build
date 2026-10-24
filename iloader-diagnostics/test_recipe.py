# SPDX-License-Identifier: MIT
import importlib.util
import io
import json
import os
import re
import struct
import tempfile
import unittest
import zipfile
from unittest import mock
from pathlib import Path

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location("diagnostic_recipe", HERE / "apply.py")
recipe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recipe)
package_spec = importlib.util.spec_from_file_location("diagnostic_package", HERE / "package.py")
package = importlib.util.module_from_spec(package_spec)
package_spec.loader.exec_module(package)


def synthetic_sources():
    lock = '''version = 4
[[package]]
name = "iloader"
version = "2.4.0"
dependencies = [
 "reqwest",
 "rootcause",
]
[[package]]
name = "reqwest-middleware"
version = "0.5.2"
checksum = "SYNTHETIC_CHECKSUM"
'''
    return {
        "src-tauri/src/error.rs": "        let report_str = report.to_string();\n",
        "src-tauri/src/lib.rs": "mod logging;\n" + "tracing_subscriber::filter::LevelFilter::DEBUG\n" * 2,
        "src-tauri/Cargo.toml": 'reqwest = "0.13.2"\n',
        "src-tauri/Cargo.lock": lock,
        "src-tauri/tauri.conf.json": '{"title": "iloader", "identifier": "me.nabdev.iloader"}',
        "src/App.tsx": "      </header>\n<unchanged-synthetic-content/>\n",
    }


class RecipeTests(unittest.TestCase):
    def test_exact_six_file_surface(self):
        original = synthetic_sources()
        patched = recipe.transform(original)
        self.assertEqual(set(patched), set(recipe.CONFIG["blobs"]))
        self.assertTrue(all(patched[p] != original[p] for p in original))

    def test_rejects_second_application(self):
        with self.assertRaises(ValueError):
            recipe.transform(recipe.transform(synthetic_sources()))

    def test_rejects_missing_and_ambiguous_anchor(self):
        for value in ("", 'reqwest = "0.13.2"\n' * 2):
            original = synthetic_sources()
            original["src-tauri/Cargo.toml"] = value
            with self.assertRaises(ValueError):
                recipe.transform(original)

    def test_dependency_graph_and_checksums_are_unchanged(self):
        original = synthetic_sources()
        patched = recipe.transform(original)
        key = "src-tauri/Cargo.lock"
        self.assertEqual(recipe.package_graph(patched[key]), recipe.package_graph(original[key]))
        self.assertIn('reqwest-middleware = "=0.5.2"', patched["src-tauri/Cargo.toml"])

    def test_logs_only_accept_sanitized_target(self):
        patched = recipe.transform(synthetic_sources())
        source = patched["src-tauri/src/lib.rs"]
        self.assertEqual(source.count(recipe.LOG_FILTER), 2)
        self.assertNotIn("LevelFilter::DEBUG", source)
        self.assertNotIn("danger_accept_invalid_certs", "\n".join(patched.values()))

    def test_non_network_error_branch_is_retained(self):
        patched = recipe.transform(synthetic_sources())["src-tauri/src/error.rs"]
        self.assertIn("summarize_report(&report)", patched)
        self.assertIn("report.to_string()", patched)
        self.assertIn('target: "pivot_network_diagnostics"', patched)

    def test_branding_has_clear_unofficial_notice_and_upstream_link(self):
        patched = recipe.transform(synthetic_sources())
        self.assertIn("UNOFFICIAL diagnostic D1", patched["src/App.tsx"])
        self.assertIn('href="https://iloader.app"', patched["src/App.tsx"])
        self.assertIn("UNOFFICIAL Diagnostic D1", patched["src-tauri/tauri.conf.json"])
        self.assertIn('"identifier": "me.nabdev.iloader"', patched["src-tauri/tauri.conf.json"])

    def test_native_tests_are_exactly_eighteen_and_synthetic(self):
        source = (HERE / "network_diagnostics.rs").read_text(encoding="utf-8")
        self.assertEqual(source.count("#[test]"), 18)
        self.assertNotIn(".send()", source)
        self.assertNotIn(".await", source)
        self.assertNotIn("developerservices2.apple.com", source)

    def test_native_reports_match_production_dynamic_sendsync_type(self):
        source = (HERE / "network_diagnostics.rs").read_text(encoding="utf-8")
        fixtures = source.split("#[cfg(test)]", 1)[1]
        self.assertEqual(fixtures.count("let report: rootcause::Report = rootcause::Report::new_sendsync("), 3)
        self.assertEqual(fixtures.count(".into_dynamic();"), 3)
        self.assertNotIn("use rootcause::prelude", fixtures)

    def test_module_never_formats_raw_error_or_url_into_output(self):
        source = (HERE / "network_diagnostics.rs").read_text(encoding="utf-8")
        render = source.split("    fn render(&self)", 1)[1].split("fn summarize_error", 1)[0]
        self.assertNotIn("error", render)
        self.assertNotIn("text", render)
        self.assertIn("MAX_DEPTH: usize = 12", source)

    def test_pins_are_public_and_complete(self):
        config = json.loads((HERE / "upstream.json").read_text(encoding="utf-8"))
        self.assertEqual(len(config["blobs"]), 6)
        self.assertEqual(len(config["protected_blobs"]), 4)
        self.assertEqual(config["native_test_count"], 18)
        self.assertEqual(config["repository"], "https://github.com/nab138/iloader.git")

    def test_native_result_gate_accepts_only_exact_success(self):
        expected = re.findall(r"#\[test\]\s+fn ([a-z0-9_]+)", (HERE / "network_diagnostics.rs").read_text(encoding="utf-8"))
        names = "\n".join("test network_diagnostics::tests::" + name + " ... ok" for name in expected)
        text = names + "\ntest result: ok. 18 passed; 0 failed; 0 ignored;"
        self.assertEqual(package.native_result(text)["passed"], 18)
        for invalid in (text.replace("0 ignored", "1 ignored"), text.replace("18 passed", "17 passed"),
                        text.replace(expected[1], expected[0]), text.replace(expected[0] + " ... ok", expected[0] + " ... FAILED"),
                        text.replace(expected[0], "unknown_fixture")):
            with self.assertRaises(ValueError):
                package.native_result(invalid)

    def test_executable_gate_requires_unsigned_amd64_with_marker(self):
        data = bytearray(2048)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 0x80)
        data[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<H", data, 0x84, 0x8664)
        struct.pack_into("<H", data, 0x98, 0x20B)
        data[0x300:0x30C] = b"PIVOT-NET-D1"
        package.verify_pe(data)
        for offset, replacement in ((0, b"NO"), (0x84, b"\x4c\x01"), (0x300, b"XXXXXXXXXXXX"),
                                    (0x98 + 112 + 32, b"\x01\x00\x00\x00")):
            damaged = bytearray(data)
            damaged[offset:offset + len(replacement)] = replacement
            with self.assertRaises(ValueError):
                package.verify_pe(damaged)

    def test_cargo_metadata_uses_strict_utf8_not_windows_codepage(self):
        expected = {"packages": [{"name": "synthetic", "description": "Łódź 漢字 🏋"}]}
        raw = json.dumps(expected, ensure_ascii=False).encode("utf-8")
        with mock.patch.object(package.subprocess, "check_output", return_value=raw) as command:
            self.assertEqual(package.cargo_metadata(HERE), expected)
            self.assertNotIn("text", command.call_args.kwargs)
        with mock.patch.object(package.subprocess, "check_output", return_value=b"\xff"):
            with self.assertRaises(UnicodeDecodeError):
                package.cargo_metadata(HERE)

    def test_zip_normalizes_epoch_license_timestamps_without_changing_bytes(self):
        scratch = HERE.parent / "build"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="synthetic-license-", dir=scratch) as temporary:
            path = Path(temporary) / "LICENSE"
            expected = b"Synthetic public license fixture\n"
            path.write_bytes(expected)
            os.utime(path, (0, 0))
            with zipfile.ZipFile(io.BytesIO(), "w") as baseline:
                with self.assertRaises(ValueError):
                    baseline.write(path, "fixture/LICENSE")
            data = io.BytesIO()
            with zipfile.ZipFile(data, "w") as archive:
                package.zip_entry(archive, "fixture/LICENSE", path.read_bytes())
                package.zip_entry(archive, "fixture/LICENSE", expected)
                with self.assertRaises(ValueError):
                    package.zip_entry(archive, "fixture/LICENSE", b"conflicting fixture")
                for unsafe in ("../escape", "/absolute", "C:/absolute", "fixture\\escape"):
                    with self.assertRaises(ValueError):
                        package.zip_entry(archive, unsafe, b"fixture")
            with zipfile.ZipFile(io.BytesIO(data.getvalue())) as archive:
                self.assertEqual(archive.namelist(), ["fixture/LICENSE"])
                self.assertEqual(archive.read("fixture/LICENSE"), expected)
                self.assertEqual(archive.getinfo("fixture/LICENSE").date_time, (1980, 1, 1, 0, 0, 0))
                self.assertIsNone(archive.testzip())

    def test_workflow_is_public_only_and_never_launches_or_uploads_raw_logs(self):
        source = (HERE.parent / ".github/workflows/iloader-diagnostics.yml").read_text(encoding="utf-8")
        self.assertIn("github.event.repository.private == false", source)
        self.assertIn("runs-on: windows-latest", source)
        self.assertIn("persist-credentials: false", source)
        self.assertIn("cargo test --release --locked --lib network_diagnostics::tests::", source)
        self.assertIn("--no-bundle --config src-tauri/ci.conf.json", source)
        self.assertNotIn("secrets.", source)
        self.assertNotIn("if: failure()", source)
        self.assertNotIn("Start-Process", source)
        self.assertNotIn("self-hosted", source)
        self.assertEqual(source.count("uses: actions/upload-artifact"), 1)
        self.assertIn("path: build/diagnostic-candidate/", source)


if __name__ == "__main__":
    unittest.main()
