"""Catalog overlay contracts, plus a real small SquashFS when tools exist."""

import copy
import json
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

from test_policy import fixture, overlay_fixture
import test_policy as policy_tests
from asu.ax6000_policy import PolicyError, protected_packages
from asu.overlay_policy import (
    decode_overlay,
    promoted_overlay,
    verify_sysupgrade_overlay,
    verify_apk_pins,
    validate_apk_roots,
    static_fit_root,
)


class OverlayTests(unittest.TestCase):
    def test_static_ubootmod_fit_root_refs_ranges_and_hashes(self):
        from fit_fixture import fit_fixture

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sysupgrade.itb"
            path.write_bytes(fit_fixture() + b"fwtool-trailer")
            self.assertEqual(static_fit_root(path), b"hsqs" + b"\0" * 4092)
            for kwargs in (
                {"relative": True},
                {"bad_hash": True},
                {"overlap": True},
                {"ambiguity": True},
                {"wide_cell": True},
                {"root_ref": "kernel-1"},
            ):
                with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                    path.write_bytes(fit_fixture(**kwargs))
                    static_fit_root(path)

    def test_apk_source_policy_root_universe_can_exceed_installed_request_limit(self):
        roots = ["core-" + str(number).zfill(5) for number in range(3006)]
        validate_apk_roots({"apk_protected_roots": roots}, "apk")
        with self.assertRaises(PolicyError):
            validate_apk_roots(
                {
                    "apk_protected_roots": [
                        "core-" + str(number).zfill(5) for number in range(10001)
                    ]
                },
                "apk",
            )

    def test_required_exact_paths_bytes_modes_and_bounds(self):
        for manager in ("apk", "opkg"):
            source = overlay_fixture(manager)
            self.assertEqual(
                len(decode_overlay(source, manager)), 7 if manager == "apk" else 5
            )
            for mutation in (
                "missing",
                "escape",
                "unreviewed",
                "mode",
                "digest",
                "oversized",
                "base64",
            ):
                with self.subTest(manager=manager, mutation=mutation):
                    candidate = copy.deepcopy(source)
                    path = "usr/sbin/ax6000-install-feed"
                    if mutation == "missing":
                        del candidate[path]
                    elif mutation in ("escape", "unreviewed"):
                        candidate[
                            "../etc/shadow"
                            if mutation == "escape"
                            else "etc/uci-defaults/00-unreviewed"
                        ] = candidate[path]
                    elif mutation == "mode":
                        candidate[path]["mode"] = 0o644
                    elif mutation == "digest":
                        candidate[path]["sha256"] = "0" * 64
                    elif mutation == "oversized":
                        candidate[path]["content_base64"] = "A" * (90 * 1024)
                    else:
                        candidate[path]["content_base64"] = "***"
                    with self.assertRaises(ValueError):
                        decode_overlay(candidate, manager)

    def test_catalog_requires_overlay_and_identity_overrides_only_seed_file(self):
        f = fixture()
        helper = policy_tests.PolicyTests()
        c = helper.load(f)
        overlay = promoted_overlay(c)
        self.assertEqual(json.loads(overlay["etc/asu-cohort.json"][0]), c.identity)
        self.assertEqual(
            overlay["usr/sbin/ax6000-install-feed"], (b"fixture-only\n", 0o755)
        )
        del f["rootfs_overlay"]
        with self.assertRaises(PolicyError):
            helper.load(f)

    def test_apk_attested_roots_required_and_userspace_need_not_be_pinned(self):
        f = fixture()
        del f["apk_protected_roots"]
        with self.assertRaises(PolicyError):
            policy_tests.PolicyTests().load(f)
        c = policy_tests.PolicyTests().load()
        manifest = {
            name: c.data["packages"][name] for name in protected_packages(c.data)
        }
        pins = "".join(
            name + "=" + version + "\n"
            for name, version in sorted(manifest.items())
            if name != "luci-app-attendedsysupgrade"
        ).encode()
        files = {
            "etc/apk/world": pins + b"luci-app-attendedsysupgrade\n",
            "etc/apk/ax6000-protected.list": pins,
        }
        verify_apk_pins(c, manifest, lambda path, *_: files[path])
        f = fixture()
        f["apk_protected_roots"].append("luci-app-attendedsysupgrade")
        f["apk_protected_roots"].sort()
        with self.assertRaisesRegex(PolicyError, "mandatory native pin"):
            verify_apk_pins(
                policy_tests.PolicyTests().load(f),
                manifest,
                lambda path, *_: files[path],
            )

    def test_apk_generated_world_preserves_exact_native_pins(self):
        c = policy_tests.PolicyTests().load()
        manifest = {
            name: c.data["packages"][name] for name in protected_packages(c.data)
        }
        pins = "".join(
            name + "=" + version + "\n" for name, version in sorted(manifest.items())
        ).encode()
        files = {"etc/apk/world": pins, "etc/apk/ax6000-protected.list": pins}
        verify_apk_pins(c, manifest, lambda path, *_: files[path])
        for wrong in (
            b"kernel@public=wrong\n",
            pins.replace(b"busybox=", b"busybox@public="),
            pins.replace(b"busybox=1.0-r1\n", b""),
        ):
            files["etc/apk/world"] = wrong
            with self.assertRaises(PolicyError):
                verify_apk_pins(c, manifest, lambda path, *_: files[path])

    @unittest.skipUnless(
        shutil.which("mksquashfs") and shutil.which("unsquashfs"),
        "real SquashFS tools unavailable in this test environment",
    )
    def test_actual_sysupgrade_squashfs_overlay_bytes_and_modes(self):
        f = fixture()
        stock = "xiaomi_redmi-router-ax6000-stock"
        ubootmod = "xiaomi_redmi-router-ax6000-ubootmod"
        f["profiles"][ubootmod] = copy.deepcopy(f["profiles"][stock])
        f["profiles"][ubootmod]["supported_devices"] = [
            "xiaomi,redmi-router-ax6000-ubootmod"
        ]
        c = policy_tests.PolicyTests().load(f)
        profile = stock
        manifest = {
            name: c.data["packages"][name] for name in protected_packages(c.data)
        }
        with tempfile.TemporaryDirectory() as tmp:
            builder = Path(tmp)
            source = builder / "source"
            for path, (content, mode) in promoted_overlay(c).items():
                file = source / path
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(content)
                file.chmod(mode)
            pins = "".join(
                name + "=" + version + "\n"
                for name, version in sorted(manifest.items())
            ).encode()
            for path in ("etc/apk/world", "etc/apk/ax6000-protected.list"):
                file = source / path
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(pins)
                file.chmod(0o644)

            class Container:
                def put_archive(self, destination, data):
                    import io

                    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                        assert archive.getnames() == [".asu-inspected-root.squashfs"]
                        archive.extractall(builder, filter="data")
                    return True

                def exec_run(self, command, **kwargs):
                    args = [
                        str(builder / arg.removeprefix("/builder/"))
                        if arg.startswith("/builder/")
                        else arg
                        for arg in command
                    ]
                    if command[0] == "/builder/staging_dir/host/bin/unsquashfs4":
                        args[0] = shutil.which("unsquashfs")
                    process = subprocess.run(args, capture_output=True, timeout=30)
                    return process.returncode, (process.stdout, process.stderr)

            output = builder / ("a" * 64)
            output.mkdir()
            filename = "fixture-sysupgrade.bin"

            def metadata():
                (output / "profiles.json").write_text(
                    json.dumps(
                        {
                            "profiles": {
                                profile: {
                                    "images": [
                                        {
                                            "type": "sysupgrade",
                                            "filesystem": "squashfs",
                                            "name": filename,
                                        }
                                    ]
                                }
                            }
                        }
                    )
                )

            metadata()

            def build():
                squash = builder / "root.squashfs"
                subprocess.run(
                    [
                        "mksquashfs",
                        str(source),
                        str(squash),
                        "-noappend",
                        "-no-progress",
                        "-processors",
                        "1",
                        "-mem",
                        "32M",
                    ],
                    check=True,
                    capture_output=True,
                    timeout=30,
                )
                if profile == ubootmod:
                    from fit_fixture import fit_fixture

                    (output / filename).write_bytes(
                        fit_fixture(root_data=squash.read_bytes())
                    )
                else:
                    with tarfile.open(output / filename, "w") as archive:
                        archive.add(squash, arcname="sysupgrade-fixture/root")
                (builder / ".asu-inspected-root.squashfs").unlink(missing_ok=True)

            build()
            verified = verify_sysupgrade_overlay(
                Container(), c, output, "a" * 64, manifest, profile
            )
            self.assertEqual(
                set(verified),
                set(c.data["rootfs_overlay"])
                | {"etc/apk/world", "etc/apk/ax6000-protected.list"},
            )
            installer = source / "usr/sbin/ax6000-install-feed"
            installer.chmod(0o644)
            build()
            with self.assertRaisesRegex(PolicyError, "mode differs"):
                verify_sysupgrade_overlay(
                    Container(), c, output, "a" * 64, manifest, profile
                )
            installer.chmod(0o755)
            installer.write_bytes(b"tampered\n")
            build()
            with self.assertRaisesRegex(PolicyError, "bytes differ"):
                verify_sysupgrade_overlay(
                    Container(), c, output, "a" * 64, manifest, profile
                )

            installer.write_bytes(b"fixture-only\n")
            profile = ubootmod
            filename = "fixture-sysupgrade.itb"
            metadata()
            build()
            self.assertIn(
                "etc/asu-cohort.json",
                verify_sysupgrade_overlay(
                    Container(), c, output, "a" * 64, manifest, profile
                ),
            )


if __name__ == "__main__":
    unittest.main()
