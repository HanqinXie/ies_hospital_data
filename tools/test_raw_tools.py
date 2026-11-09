"""Standard-library regression tests for raw packaging and restoration."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile


HERE = Path(__file__).resolve().parent
WORK = HERE.parents[1]


class RawToolsTests(unittest.TestCase):
    def setUp(self):
        base = WORK / "test_work"
        base.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="raw_test_", dir=base)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.work = self.root / "package"
        self.work.mkdir()
        self.scopes = []

    def tearDown(self):
        self.temp.cleanup()

    def run_tool(self, tool, *args, ok=True):
        script = HERE / tool
        self.assertTrue(script.is_file(), f"Required implementation missing: {tool}")
        result = subprocess.run([sys.executable, str(script), *map(str, args)],
                                capture_output=True, text=True, encoding="utf-8")
        if ok:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def scope(self, records):
        path = self.root / f"scope_{len(self.scopes)}.json"
        path.write_text(json.dumps(records), encoding="utf-8")
        self.scopes.append(path)
        return path

    def record(self, name, content, group="A", logical=None):
        path = self.source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return dict(source_path=str(path), archive_path=logical or "raw/" + name,
                    group=group, role="original_binary", bytes=len(content))

    def pack(self, ok=True):
        args = ["--work-root", self.work, "--target-raw-bytes", 4000,
                "--chunk-bytes", 3000, "--max-asset-bytes", 20000]
        for scope in self.scopes:
            args.extend(["--scope", scope])
        return self.run_tool("package_raw.py", *args, ok=ok)

    def restore(self, *args, ok=True):
        return self.run_tool("restore_raw.py", "--manifest", self.work / "repo/catalog/RAW_MANIFEST.json",
                             "--assets", self.work / "assets", *args, ok=ok)

    def manifest(self):
        return json.loads((self.work / "repo/catalog/RAW_MANIFEST.json").read_text(encoding="utf-8"))

    def write_manifest(self, value):
        (self.work / "repo/catalog/RAW_MANIFEST.json").write_text(json.dumps(value), encoding="utf-8")

    def test_binary_roundtrip_fragments_cross_volumes_and_duplicate_source_roles(self):
        binary = bytes(range(256)) * 47
        row = self.record("a.bin", binary)
        snapshot = Path(row["source_path"]).stat()
        second = dict(row, group="B", role="second_role", archive_path="B/alias.bin")
        self.scope([row]); self.scope([second])
        self.pack()
        manifest = self.manifest()
        self.assertEqual(len(manifest["files"]), 1)
        file = manifest["files"][0]
        self.assertEqual(set(file["groups"]), {"A", "B"})
        self.assertIn("second_role", file["roles"])
        self.assertGreater(len({x["asset"] for x in file["fragments"]}), 1)
        self.assertEqual(file["sha256"], hashlib.sha256(binary).hexdigest())
        self.restore("--verify-only")
        destination = self.root / "restored"
        self.restore("--destination", destination)
        self.assertEqual((destination / "raw/a.bin").read_bytes(), binary)
        self.assertEqual((destination / "B/alias.bin").read_bytes(), binary)
        self.assertEqual(Path(row["source_path"]).read_bytes(), binary)
        self.assertEqual(Path(row["source_path"]).stat().st_mtime_ns, snapshot.st_mtime_ns)
        self.assertTrue(all(p.stat().st_size <= 20000 for p in (self.work / "assets").glob("*.zip")))

    def test_original_zip_bytes_stored_and_jsonl_deflated(self):
        original = self.source / "attempt.zip"
        with zipfile.ZipFile(original, "w", compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr("trace.jsonl", '{"demand":3}\n' * 10)
        content = original.read_bytes()
        row = dict(source_path=str(original), archive_path="raw/attempt.zip", group="D",
                   role="original_zip", bytes=len(content))
        text = self.record("trace.jsonl", b'{"raw":true}\n' * 1000)
        self.scope([row, text]); self.pack(); manifest = self.manifest()
        for file in manifest["files"]:
            for fragment in file["fragments"]:
                with zipfile.ZipFile(self.work / "assets" / fragment["asset"]) as z:
                    kind = z.getinfo(fragment["member"]).compress_type
                    self.assertEqual(kind, zipfile.ZIP_STORED if file["archive_path"].endswith(".zip")
                                     else zipfile.ZIP_DEFLATED)
        self.restore("--destination", self.root / "restored")
        self.assertEqual((self.root / "restored/raw/attempt.zip").read_bytes(), content)

    def test_tampered_asset_rejected_before_restore(self):
        self.scope([self.record("a.bin", b"abcd" * 1500)]); self.pack()
        asset = self.work / "assets" / self.manifest()["assets"][0]["name"]
        data = bytearray(asset.read_bytes()); data[len(data) // 2] ^= 1; asset.write_bytes(data)
        destination = self.root / "restored"
        self.restore("--destination", destination, ok=False)
        self.assertFalse(destination.exists())

    def test_fragment_hash_tamper_detected(self):
        self.scope([self.record("a.bin", b"abcd" * 1500)]); self.pack()
        manifest = self.manifest(); manifest["files"][0]["fragments"][0]["sha256"] = "0" * 64
        self.write_manifest(manifest)
        self.restore("--verify-only", ok=False)

    def test_manifest_path_traversal_rejected(self):
        self.scope([self.record("a.bin", b"abcd")]); self.pack()
        manifest = self.manifest(); manifest["files"][0]["archive_path"] = "../escape.bin"
        manifest["files"][0]["archive_paths"] = ["../escape.bin"]
        self.write_manifest(manifest)
        destination = self.root / "restored"
        self.restore("--destination", destination, ok=False)
        self.assertFalse((self.root / "escape.bin").exists())

    def test_asset_path_traversal_rejected(self):
        self.scope([self.record("a.bin", b"abcd")]); self.pack()
        manifest = self.manifest(); manifest["assets"][0]["name"] = "../outside.zip"
        self.write_manifest(manifest)
        self.restore("--verify-only", ok=False)

    def test_existing_inconsistent_file_not_overwritten(self):
        self.scope([self.record("a.bin", b"abcd")]); self.pack()
        destination = self.root / "restored"; (destination / "raw").mkdir(parents=True)
        target = destination / "raw/a.bin"; target.write_bytes(b"keep me")
        self.restore("--destination", destination, ok=False)
        self.assertEqual(target.read_bytes(), b"keep me")

    def test_secret_refusal_does_not_print_secret(self):
        secret = b"ghp_" + b"a" * 36
        self.scope([self.record("trace.jsonl", b'{"token":"' + secret + b'"}')])
        result = self.pack(ok=False)
        self.assertNotIn(secret.decode(), result.stdout + result.stderr)
        self.assertFalse((self.work / "repo/catalog/RAW_MANIFEST.json").exists())

    def test_short_nonempty_wlssecret_is_refused(self):
        self.scope([self.record("trace.jsonl", b'{"WLSSECRET":"abc"}')])
        self.pack(ok=False)

    def test_empty_and_null_wlssecret_are_not_credentials(self):
        self.scope([self.record("trace.jsonl", b'{"WLSSECRET":""}\n{"WLSSECRET":null}')])
        self.pack()
        self.restore("--verify-only")

    def test_unicode_logical_path_roundtrip(self):
        name = "\u533b\u9662/\u539f\u59cb.jsonl"
        self.scope([self.record(name, b'{"original":true}\n')])
        self.pack(); self.restore("--destination", self.root / "restored")
        self.assertEqual((self.root / "restored/raw" / name).read_bytes(), b'{"original":true}\n')

    def test_zero_length_source_roundtrip(self):
        self.scope([self.record("SOLVER_LOG.jsonl", b"")]); self.pack()
        file = self.manifest()["files"][0]
        self.assertEqual(file["bytes"], 0)
        self.assertEqual(file["sha256"], hashlib.sha256(b"").hexdigest())
        self.assertEqual(len(file["fragments"]), 1)
        self.assertEqual(file["fragments"][0]["bytes"], 0)
        self.restore("--verify-only"); self.restore("--destination", self.root / "restored")
        self.assertEqual((self.root / "restored/raw/SOLVER_LOG.jsonl").read_bytes(), b"")

    def test_atomic_publish_refuses_existing_destination(self):
        import restore_raw
        self.assertTrue(callable(getattr(restore_raw, "publish_no_clobber", None)),
                        "Atomic cross-platform no-clobber publication is not implemented")
        temporary = self.root / "new.raw-restoring"; temporary.write_bytes(b"new")
        target = self.root / "existing.bin"; target.write_bytes(b"old")
        with self.assertRaises(FileExistsError):
            restore_raw.publish_no_clobber(temporary, target)
        self.assertEqual(target.read_bytes(), b"old")
        self.assertEqual(temporary.read_bytes(), b"new")
        target.unlink()
        restore_raw.publish_no_clobber(temporary, target)
        self.assertEqual(target.read_bytes(), b"new")
        self.assertFalse(temporary.exists())

    def test_forbidden_source_and_nested_zip_member_rejected(self):
        self.scope([self.record("weather.epw", b"forbidden")]); self.pack(ok=False)
        self.scopes.clear()
        original = self.source / "attempt.zip"
        with zipfile.ZipFile(original, "w") as z:
            z.writestr("nested/year_8760.csv", "1,2")
        self.scope([dict(source_path=str(original), archive_path="raw/attempt.zip", group="D",
                         role="raw_zip", bytes=original.stat().st_size)])
        self.pack(ok=False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
