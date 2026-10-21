import os
import tempfile
import unittest
from pathlib import Path
from asu.cache_policy import prune_cache


class CacheTests(unittest.TestCase):
    def test_invalid_partial_cache_removed_before_republication(self):
        import hashlib
        import json
        from unittest.mock import patch
        from asu.cache_policy import discard_invalid_build_cache
        from asu.config import settings
        from asu.store import LocalStore

        with tempfile.TemporaryDirectory() as tmp:
            build_hash = "a" * 64
            root = Path(tmp) / "store" / build_hash
            root.mkdir(parents=True)
            identity = {"cohort": "fixture"}
            record = {
                "name": "image.bin",
                "size": 2,
                "sha256": hashlib.sha256(b"fw").hexdigest(),
            }
            metadata = {
                "ax6000": identity,
                "profiles": {"fixture": {"images": [record]}},
            }
            (root / "profiles.json").write_text(json.dumps(metadata))
            (root / "image.bin").write_bytes(b"fw")
            self.assertFalse(discard_invalid_build_cache(tmp, build_hash, identity))
            for state in ("missing", "corrupt", "metadata"):
                with self.subTest(state=state):
                    root.mkdir(exist_ok=True)
                    (root / "profiles.json").write_text(json.dumps(metadata))
                    (root / "image.bin").write_bytes(b"fw")
                    if state == "missing":
                        (root / "image.bin").unlink()
                    elif state == "corrupt":
                        (root / "image.bin").write_bytes(b"xx")
                    else:
                        (root / "profiles.json").write_text("{")
                    self.assertTrue(
                        discard_invalid_build_cache(tmp, build_hash, identity)
                    )
                    self.assertFalse(root.exists())
                    private = Path(tmp) / "rebuilt"
                    private.mkdir()
                    (private / "image.bin").write_bytes(b"fw")
                    with patch.object(settings, "public_path", Path(tmp)):
                        LocalStore().upload_dir(private, build_hash)
                    self.assertEqual((root / "image.bin").read_bytes(), b"fw")

    def test_age_and_size_only_owned_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "store"
            root.mkdir()
            for name, timestamp in [
                ("a" * 64, 10),
                ("b" * 64, 80),
                ("c" * 64, 90),
                ("unrelated", 1),
            ]:
                p = root / name
                p.mkdir()
                (p / "image").write_bytes(b"x" * 10)
                os.utime(p, (timestamp, timestamp))
            self.assertEqual(
                prune_cache(tmp, max_bytes=10, max_age=50, now=100),
                ["a" * 64, "b" * 64],
            )
            self.assertTrue((root / "unrelated").exists())
            self.assertTrue((root / ("c" * 64)).exists())

    def test_symlinks_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "store" / ("a" * 64)
            p.mkdir(parents=True)
            (p / "bad").symlink_to("/etc/passwd")
            with self.assertRaises(ValueError):
                prune_cache(tmp, max_bytes=0)


if __name__ == "__main__":
    unittest.main()
