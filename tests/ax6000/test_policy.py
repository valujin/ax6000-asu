"""Unactivated fixtures: none of these catalog entries authorizes a live build."""

import copy
import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from asu.ax6000_policy import (
    Catalog,
    PolicyError,
    cache_hash,
    validate_request,
    validate_manifest,
    image_package_specs,
    normalize_emitted_manifest,
)


def overlay_fixture(manager="apk"):
    paths = {
        "etc/asu-cohort.json": 0o644,
        "etc/uci-defaults/99-ax6000-asu": 0o755,
        "usr/sbin/ax6000-install-feed": 0o755,
    }
    paths.update(
        {
            "etc/apk/repositories.d/distfeeds.list": 0o644,
            "etc/apk/repositories.d/customfeeds.list": 0o644,
            "etc/apk/keys/repository-apk.pem": 0o644,
            "etc/ax6000/repository.pub": 0o644,
        }
        if manager == "apk"
        else {
            "etc/opkg/distfeeds.conf": 0o644,
            "etc/opkg/keys/eaad5e29fcc9ed69": 0o644,
        }
    )
    return {
        path: {
            "content_base64": base64.b64encode(b"fixture-only\n").decode(),
            "sha256": hashlib.sha256(b"fixture-only\n").hexdigest(),
            "mode": mode,
        }
        for path, mode in paths.items()
    }


def fixture():
    names = [
        "base-files",
        "busybox",
        "apk-mbedtls",
        "kernel",
        "libc",
        "kmod-mt_wifi",
        "kmod-mediatek_hnat",
        "luci-app-attendedsysupgrade",
        "tailscale",
    ]
    mandatory = names[:-1]
    return {
        "schema_version": 1,
        "rootfs_overlay": overlay_fixture(),
        "apk_protected_roots": ["base-files", "busybox", "kernel", "libc"],
        "cohort": "612-recommended",
        "package_manager": "apk",
        "seed": "a" * 64,
        "build_id": "fixture-not-promoted",
        "source_commit": "b" * 40,
        "snapshot_sha256": "c" * 64,
        "imagebuilder": {"archive_sha256": "d" * 64, "image": "sha256:" + "e" * 64},
        "firmware": {
            "version_number": "25.12-SNAPSHOT",
            "version_code": "r0+123-fixture",
            "target": "mediatek/filogic",
            "architecture": "aarch64_cortex-a53",
            "kernel_version": "6.12.108~" + "f" * 32 + "-r1",
        },
        "profiles": {
            "xiaomi_redmi-router-ax6000-stock": {
                "supported_devices": ["xiaomi,redmi-router-ax6000-stock"],
                "mandatory_packages": mandatory,
                "default_packages": mandatory,
                "max_image_size": 80 * 1024**2,
            }
        },
        "package_identities": {
            name: {
                "name": name,
                "abi": "",
                "version": (
                    "6.12.108~" + "f" * 32 + "-r1" if name == "kernel" else "1.0-r1"
                ),
                "tag": "",
            }
            for name in names
        },
        "packages": {
            name: ("6.12.108~" + "f" * 32 + "-r1" if name == "kernel" else "1.0-r1")
            for name in names
        },
        "repositories_conf": "https://example.invalid/snapshots/"
        + "c" * 64
        + "/packages/packages.adb\n",
        "repository_keys": ["untrusted comment: fixture\nfixture"],
        "promotion": {
            "verified": True,
            "native_evidence_sha256": "1" * 64,
            "imagebuilder_evidence_sha256": "2" * 64,
            "feed_evidence_sha256": "3" * 64,
        },
    }


class PolicyTests(unittest.TestCase):
    def load(self, obj=None):
        obj = fixture() if obj is None else obj
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "catalog.json"
            data = json.dumps(obj).encode()
            p.write_bytes(data)
            return Catalog.load(p, hashlib.sha256(data).hexdigest(), obj["cohort"])

    def request(self, cat):
        return {
            "version": "25.12-SNAPSHOT",
            "target": "mediatek/filogic",
            "profile": "xiaomi,redmi-router-ax6000-stock",
            "packages": ["busybox"],
            "ax6000": cat.identity,
            "installed_package_manager": cat.data["package_manager"],
        }

    def test_mandatory_union_and_layout_normalization(self):
        c = self.load()
        r = validate_request(c, self.request(c))
        self.assertEqual(r["profile"], "xiaomi_redmi-router-ax6000-stock")
        self.assertIn("kmod-mt_wifi", r["packages"])
        self.assertNotIn("tailscale", r["packages"])

    def test_public_tag_specs_are_trusted_only_and_kernel_stays_pinned(self):
        f = fixture()
        f["packages"]["public-foo"] = "2.3-r1"
        f["package_identities"]["public-foo"] = {
            "name": "public-foo",
            "abi": "",
            "version": "2.3-r1",
            "tag": "public",
        }
        f["repositories_conf"] += (
            "@public https://example.invalid/" + "c" * 64 + "/public/packages.adb\n"
        )
        f["package_specs"] = {"public-foo": "public-foo@public=2.3-r1"}
        f["public_policy"] = {
            "mode": "validated-subset",
            "distribution": "immortalwrt",
            "tag": "public",
        }
        f["apk_repositories"] = {
            "native": {
                "url": "file:///builder/packages/packages.adb",
                "sha256": "1" * 64,
            },
            "public-packages": {
                "url": "https://example.invalid/" + "c" * 64 + "/public/packages.adb",
                "sha256": "2" * 64,
            },
        }
        f["package_origins"] = {
            name: {
                "repository": "public-packages" if item["tag"] else "native",
                "filename": item["name"] + "-" + item["version"] + ".apk",
                "identity_sha256": "3" * 64,
            }
            for name, item in f["package_identities"].items()
        }
        c = self.load(f)
        r = self.request(c)
        r["packages"].append("public-foo")
        r = validate_request(c, r)
        specs = image_package_specs(c, r["packages"])
        self.assertIn("public-foo@public=2.3-r1", specs)
        self.assertIn("kernel=" + c.data["firmware"]["kernel_version"], specs)
        with self.assertRaises(PolicyError):
            validate_request(c, {**r, "packages": ["public-foo@public"]})
        f["package_identities"]["kernel"]["tag"] = "public"
        with self.assertRaises(PolicyError):
            self.load(f)

    def test_emitted_abi_names_resolve_only_verified_actual_identity(self):
        f = fixture()
        f["packages"]["libexample"] = "1-r1"
        f["package_identities"]["libexample"] = {
            "name": "libexample202610",
            "abi": "202610",
            "version": "1-r1",
            "tag": "",
        }
        c = self.load(f)
        self.assertEqual(
            normalize_emitted_manifest(c, {"libexample202610": "1-r1"}),
            {"libexample": "1-r1"},
        )
        self.assertEqual(
            image_package_specs(c, ["libexample"]), ["libexample202610=1-r1"]
        )
        for invalid in ("libexample", "libexample2025", "unknown-package"):
            with self.subTest(invalid=invalid), self.assertRaises(PolicyError):
                normalize_emitted_manifest(c, {invalid: "1-r1"})

        from asu.manifest_policy import verify_emitted_manifest

        request = self.request(c)
        request["packages"].append("libexample")
        request = validate_request(c, request)
        expected = {p: c.data["packages"][p] for p in request["packages"]}
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "firmware.manifest"
            content = "".join(
                c.data["package_identities"][name]["name"] + " " + version + "\n"
                for name, version in expected.items()
            )
            manifest.write_text(content)
            self.assertEqual(
                verify_emitted_manifest(c, request, tmp, expected), expected
            )
            manifest.write_text(content.replace("libexample202610 ", "libexample "))
            with self.assertRaises(PolicyError):
                verify_emitted_manifest(c, request, tmp, expected)

    def test_actual_emitted_file_must_match_preflight_closure(self):
        from asu.manifest_policy import verify_emitted_manifest

        c = self.load()
        r = validate_request(c, self.request(c))
        expected = {p: c.data["packages"][p] for p in r["packages"]}
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "firmware.manifest"
            p.write_text(
                "".join(
                    name + " " + version + "\n" for name, version in expected.items()
                )
            )
            self.assertEqual(verify_emitted_manifest(c, r, tmp, expected), expected)
            p.write_text(p.read_text().replace("libc 1.0-r1", "libc 0.1-r1"))
            with self.assertRaises(PolicyError):
                verify_emitted_manifest(c, r, tmp, expected)
            p.write_text("kernel wrong\nkernel wrong\n")
            with self.assertRaises(ValueError):
                verify_emitted_manifest(c, r, tmp, expected)

    def test_manifest_dependency_versions_cannot_fall_back_to_native_old_packages(self):
        c = self.load()
        r = validate_request(c, self.request(c))
        manifest = {p: c.data["packages"][p] for p in r["packages"]}
        validate_manifest(c, r, manifest)
        with self.assertRaises(PolicyError):
            validate_manifest(c, r, {**manifest, "libc": "old-native-version"})
        with self.assertRaises(PolicyError):
            validate_manifest(c, r, {**manifest, "foreign-dependency": "1-r1"})

    def test_opkg_66_and_apk_612_keep_separate_managers(self):
        f = fixture()
        f["cohort"] = "66"
        f["package_manager"] = "opkg"
        f["rootfs_overlay"] = overlay_fixture("opkg")
        f.pop("apk_protected_roots")
        f["firmware"].update(
            version_number="24.10-SNAPSHOT",
            kernel_version="6.6.133~" + "f" * 32 + "-r1",
        )
        f["packages"]["kernel"] = f["firmware"]["kernel_version"]
        f["packages"]["opkg"] = f["packages"].pop("apk-mbedtls")
        f["package_identities"].pop("apk-mbedtls")
        f["package_identities"]["kernel"]["version"] = f["firmware"]["kernel_version"]
        f["package_identities"]["opkg"] = {
            "name": "opkg",
            "abi": "",
            "version": f["packages"]["opkg"],
            "tag": "",
        }
        for field in ["mandatory_packages", "default_packages"]:
            f["profiles"]["xiaomi_redmi-router-ax6000-stock"][field] = [
                "opkg" if p == "apk-mbedtls" else p
                for p in f["profiles"]["xiaomi_redmi-router-ax6000-stock"][field]
            ]
        f["repositories_conf"] = (
            "src/gz approved https://example.invalid/"
            + "c" * 64
            + "/packages\noption check_signature\n"
        )
        c = self.load(f)
        r = self.request(c)
        r["version"] = "24.10-SNAPSHOT"
        r.pop("installed_package_manager")
        self.assertIn("opkg", validate_request(c, r)["packages"])
        r["installed_package_manager"] = "apk"
        with self.assertRaises(PolicyError):
            validate_request(c, r)

    def test_source_package_manager_required_for_612(self):
        c = self.load()
        for manager in [None, "opkg"]:
            r = self.request(c)
            r["installed_package_manager"] = manager
            with self.assertRaises(PolicyError):
                validate_request(c, r)

    def test_declared_leading_hyphen_abi_suffixes_for_both_managers(self):
        examples = [
            ("libiptext6", "libiptext6-0", "-0"),
            ("libusb-1.0", "libusb-1.0-0", "-0"),
            ("liblz4", "liblz4-1", "-1"),
        ]
        for manager in ("apk", "opkg"):
            f = fixture()
            if manager == "opkg":
                f.update(cohort="66", package_manager="opkg")
                f["rootfs_overlay"] = overlay_fixture("opkg")
                f.pop("apk_protected_roots")
                f["firmware"].update(
                    version_number="24.10-SNAPSHOT",
                    kernel_version="6.6.133~" + "f" * 32 + "-r1",
                )
                f["packages"]["kernel"] = f["firmware"]["kernel_version"]
                f["package_identities"]["kernel"]["version"] = f["packages"]["kernel"]
                f["packages"]["opkg"] = f["packages"].pop("apk-mbedtls")
                identity = f["package_identities"].pop("apk-mbedtls")
                f["package_identities"]["opkg"] = {**identity, "name": "opkg"}
                for field in ("mandatory_packages", "default_packages"):
                    profile = f["profiles"]["xiaomi_redmi-router-ax6000-stock"]
                    profile[field] = [
                        "opkg" if p == "apk-mbedtls" else p for p in profile[field]
                    ]
                f["repositories_conf"] = (
                    "src/gz approved https://example.invalid/"
                    + "c" * 64
                    + "/packages\noption check_signature\n"
                )
            for canonical, actual, abi in examples:
                with self.subTest(manager=manager, actual=actual):
                    candidate = copy.deepcopy(f)
                    candidate["packages"][canonical] = "1.0-r1"
                    candidate["package_identities"][canonical] = {
                        "name": actual,
                        "abi": abi,
                        "version": "1.0-r1",
                        "tag": "",
                    }
                    c = self.load(candidate)
                    self.assertEqual(
                        normalize_emitted_manifest(c, {actual: "1.0-r1"}),
                        {canonical: "1.0-r1"},
                    )
                    expected = actual + ("=1.0-r1" if manager == "apk" else "")
                    self.assertEqual(image_package_specs(c, [canonical]), [expected])
                    for invalid in ("-999", "--0", "-0;id"):
                        candidate["package_identities"][canonical]["abi"] = invalid
                        with self.assertRaises(PolicyError):
                            self.load(candidate)

    def test_requested_tailscale_preserved_only_on_request(self):
        c = self.load()
        r = self.request(c)
        r["packages"].append("tailscale")
        r["installed_packages"] = ["tailscale"]
        self.assertIn("tailscale", validate_request(c, r)["packages"])

    def test_installed_tailscale_preserved_when_omitted_from_requested_names(self):
        c = self.load()
        r = self.request(c)
        r["installed_packages"] = ["tailscale"]
        self.assertIn("tailscale", validate_request(c, r)["packages"])

    def test_unknown_unsafe_or_foreign_installed_package_fails_clearly(self):
        c = self.load()
        for installed in (
            ["unavailable-installed-app"],
            ["app@public"],
            ["opkg"],
            ["kmod-mt76"],
        ):
            with self.subTest(installed=installed), self.assertRaises(PolicyError):
                validate_request(
                    c, {**self.request(c), "installed_packages": installed}
                )

    def test_collective_requested_installed_and_mandatory_bound_is_idempotent(self):
        f = fixture()
        for index in range(2048):
            name = "optional-" + str(index)
            f["packages"][name] = "1-r1"
            f["package_identities"][name] = {
                "name": name,
                "abi": "",
                "version": "1-r1",
                "tag": "",
            }
        c = self.load(f)
        request = self.request(c)
        request["packages"] = ["optional-" + str(n) for n in range(1024)]
        request["installed_packages"] = [
            "optional-" + str(n) for n in range(1024, 2048)
        ]
        with self.assertRaisesRegex(PolicyError, "Combined installed/requested"):
            validate_request(c, request)
        request["packages"] = ["optional-" + str(n) for n in range(2040)]
        request["installed_packages"] = []
        request["packages_versions"] = {"optional-0": "1-r1"}
        normalized = validate_request(c, request)
        self.assertEqual(len(normalized["packages"]), 2048)
        self.assertEqual(validate_request(c, normalized), normalized)

    def test_uninstalled_tailscale_denied(self):
        c = self.load()
        r = self.request(c)
        r["packages"].append("tailscale")
        with self.assertRaises(PolicyError):
            validate_request(c, r)

    def test_denies_client_execution_repository_partition_overrides(self):
        c = self.load()
        for key, value in [
            ("defaults", "touch /tmp/pwn"),
            ("repositories", {"x": "http://localhost"}),
            ("repository_keys", ["x"]),
            ("rootfs_size_mb", 256),
        ]:
            with self.subTest(key=key), self.assertRaises(PolicyError):
                validate_request(c, {**self.request(c), key: value})

    def test_denies_unsafe_package_names_and_foreign_stack(self):
        c = self.load()
        for pkg in [
            "-apk-mbedtls",
            "x$(touch /tmp/a)",
            "opkg",
            "kmod-mt7915e",
            "nonexistent",
        ]:
            with self.subTest(pkg=pkg), self.assertRaises(PolicyError):
                validate_request(c, {**self.request(c), "packages": [pkg]})

    def test_foreign_layout_and_cohort_and_stale_snapshot_rejected(self):
        c = self.load()
        for changes in [
            {"profile": "xiaomi_redmi-router-ax6000-ubootmod"},
            {"ax6000": {**c.identity, "cohort": "612-latest"}},
            {"ax6000": {**c.identity, "snapshot_sha256": "0" * 64}},
            {"ax6000": None},
        ]:
            with self.subTest(changes=changes), self.assertRaises(PolicyError):
                validate_request(c, {**self.request(c), **changes})

    def test_hash_binds_generation_snapshot_cohort_and_canonical_packages(self):
        c = self.load()
        r = validate_request(c, self.request(c))
        h = cache_hash(c, r)
        self.assertEqual(
            h, cache_hash(c, {**r, "packages": list(reversed(r["packages"]))})
        )
        for field in ["cohort", "build_id", "snapshot_sha256"]:
            changed = copy.deepcopy(fixture())
            changed[field] = {
                "cohort": "612-latest",
                "build_id": "fixture-new",
                "snapshot_sha256": "4" * 64,
            }[field]
            changed["repositories_conf"] = changed["repositories_conf"].replace(
                "c" * 64, changed["snapshot_sha256"]
            )
            self.assertNotEqual(h, cache_hash(self.load(changed), r))

    def test_catalog_versions_cannot_inject_make_or_shell_syntax(self):
        for version in ["$(shell touch /tmp/bad)", "1-r1\nother", "1-r1;echo-bad"]:
            f = fixture()
            f["packages"]["libc"] = version
            f["package_identities"]["libc"]["version"] = version
            with self.assertRaises(PolicyError):
                self.load(f)

    def test_unpromoted_or_wrong_catalog_sha_denied(self):
        f = fixture()
        f["promotion"]["verified"] = False
        with self.assertRaises(PolicyError):
            self.load(f)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x"
            p.write_text(json.dumps(fixture()))
            with self.assertRaises(PolicyError):
                Catalog.load(p, "0" * 64, "612-recommended")

    def test_wrong_kernel_cohort_and_moving_repo_denied(self):
        f = fixture()
        f["firmware"]["kernel_version"] = "6.6.133~" + "f" * 32 + "-r1"
        with self.assertRaises(PolicyError):
            self.load(f)
        f = fixture()
        f["repositories_conf"] = (
            "src/gz moving https://downloads.openwrt.org/snapshots/packages\n"
        )
        with self.assertRaises(PolicyError):
            self.load(f)

    def test_snapshot_installed_versions_not_target_pins(self):
        c = self.load()
        r = self.request(c)
        r["packages_versions"] = {"busybox": "0.9-r1"}
        # Client packages_versions are explicit target pins, never silently dropped.
        with self.assertRaises(PolicyError):
            validate_request(c, r)


if __name__ == "__main__":
    unittest.main()
