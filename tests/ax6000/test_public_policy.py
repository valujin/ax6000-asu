"""Frozen candidate metadata is checked against each actual solver selection."""

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from asu.ax6000_policy import PolicyError, Catalog, validate_request
from asu.public_policy import (
    validate_origin_catalog,
    validate_index_rows,
    validate_resolution,
    cache_index_path,
    size_budget,
    admitted_apk_manifest,
    require_free_space,
)


def data():
    return {
        "package_manager": "apk",
        "snapshot_sha256": "a" * 64,
        "profiles": {"fixture": {"mandatory_packages": ["libc"]}},
        "packages": {"libc": "1-r1", "userapp": "1-r1"},
        "package_identities": {
            "libc": {"name": "libc", "abi": "", "version": "1-r1", "tag": ""},
            "userapp": {
                "name": "userapp",
                "abi": "",
                "version": "1-r1",
                "tag": "public",
            },
        },
        "repositories_conf": "https://example.invalid/"
        + "a" * 64
        + "/supplement/packages.adb\n@public https://example.invalid/"
        + "a" * 64
        + "/public/packages.adb\n",
        "public_policy": {
            "mode": "candidates",
            "distribution": "immortalwrt",
            "tag": "public",
        },
        "apk_repositories": {
            "native": {
                "url": "file:///builder/packages/packages.adb",
                "sha256": "b" * 64,
            },
            "supplement": {
                "url": "https://example.invalid/"
                + "a" * 64
                + "/supplement/packages.adb",
                "sha256": "e" * 64,
            },
            "public-packages": {
                "url": "https://example.invalid/" + "a" * 64 + "/public/packages.adb",
                "sha256": "c" * 64,
            },
        },
        "package_origins": {
            "libc": {
                "repository": "native",
                "filename": "libc-1-r1.apk",
                "identity_sha256": "d" * 64,
            },
            "userapp": {
                "repository": "public-packages",
                "filename": "userapp-1-r1.apk",
                "identity_sha256": "f" * 64,
            },
        },
    }


def row(catalog, name):
    identity = catalog.data["package_identities"][name]
    origin = catalog.data["package_origins"][name]
    url = catalog.data["apk_repositories"][origin["repository"]]["url"]
    return {
        "name": identity["name"],
        "version": identity["version"],
        "arch": "aarch64_cortex-a53",
        "depends": [],
        "repositories": [url],
        "download-url": url.rsplit("/", 1)[0] + "/" + origin["filename"],
    }


class OriginPolicyTests(unittest.TestCase):
    def test_exactly_one_known_public_distribution_per_catalog(self):
        for distribution in ("immortalwrt", "openwrt"):
            with self.subTest(distribution=distribution):
                catalog = data()
                catalog["public_policy"]["distribution"] = distribution
                validate_origin_catalog(catalog)
        for distribution in (
            "unknown",
            "immortalwrt,openwrt",
            ["immortalwrt", "openwrt"],
        ):
            with self.subTest(distribution=distribution):
                catalog = data()
                catalog["public_policy"]["distribution"] = distribution
                with self.assertRaises(PolicyError):
                    validate_origin_catalog(catalog)

    def test_aggregate_sizes_and_host_reserve_reject_before_install(self):
        from unittest.mock import Mock, patch
        from asu.public_policy import MAX_INSTALLED, MAX_ARCHIVES, FREE_RESERVE

        self.assertEqual(
            size_budget(
                {"x": {"installed-size": MAX_INSTALLED, "file-size": MAX_ARCHIVES}}
            )["installed_bytes"],
            MAX_INSTALLED,
        )
        for field, value in (
            ("installed-size", MAX_INSTALLED + 1),
            ("file-size", MAX_ARCHIVES + 1),
        ):
            with self.subTest(field=field), self.assertRaises(PolicyError):
                size_budget({"x": {"installed-size": 1, "file-size": 1, field: value}})
        install = Mock()
        proof = {
            "manifest": {"x": "1-r1"},
            "selected_rows": {
                "x": {"installed-size": MAX_INSTALLED + 1, "file-size": 1}
            },
        }
        with (
            patch("asu.public_policy.verify_apk_resolution", return_value=proof),
            self.assertRaises(PolicyError),
        ):
            admitted_apk_manifest(
                None, None, ["x"], "profile", None, "/tmp", lambda _: None, install
            )
        install.assert_not_called()
        with (
            patch(
                "asu.public_policy.shutil.disk_usage",
                return_value=SimpleNamespace(free=FREE_RESERVE),
            ),
            self.assertRaises(PolicyError),
        ):
            require_free_space("/tmp", {"installed_bytes": 1, "archive_bytes": 1})

    def test_actual_installed_closure_must_equal_admitted_selection(self):
        from unittest.mock import patch

        proof = {
            "manifest": {"x": "1-r1"},
            "selected_rows": {"x": {"installed-size": 1, "file-size": 1}},
        }
        with (
            patch("asu.public_policy.verify_apk_resolution", return_value=proof),
            patch("asu.public_policy.require_free_space", return_value=10),
            patch("asu.public_policy.require_builder_free_space", return_value=10),
            self.assertRaisesRegex(PolicyError, "differs from admitted"),
        ):
            admitted_apk_manifest(
                None, None, ["x"], "profile", None, "/tmp", lambda _: None, lambda: {}
            )

    def test_new_candidate_installed_package_survives_request_normalization(self):
        from test_policy import fixture

        d = fixture()
        d["packages"]["previously-unlisted"] = "1-r1"
        d["package_identities"]["previously-unlisted"] = {
            "name": "previously-unlisted",
            "abi": "",
            "version": "1-r1",
            "tag": "public",
        }
        c = Catalog(d, "0" * 64)
        request = {
            "version": c.version,
            "target": "mediatek/filogic",
            "profile": "xiaomi_redmi-router-ax6000-stock",
            "ax6000": c.identity,
            "installed_package_manager": "apk",
            "installed_packages": ["busybox", "previously-unlisted"],
            "packages": ["busybox"],
        }
        self.assertIn("previously-unlisted", validate_request(c, request)["packages"])

    def test_native_verification_stdout_does_not_become_a_fake_package(self):
        from asu.manifest_policy import native_preflight_output, parse_manifest_text

        output = "/builder/packages/packages.adb: OK\nlibc - 1-r1\n"
        self.assertEqual(
            parse_manifest_text(native_preflight_output(output, "apk")),
            {"libc": "1-r1"},
        )
        with self.assertRaises(ValueError):
            parse_manifest_text(
                native_preflight_output(
                    output.replace("packages.adb: OK", "foreign.adb: OK"), "apk"
                )
            )

    def test_complete_catalog_origin_binding_and_request_closure(self):
        d = data()
        validate_origin_catalog(d)
        c = SimpleNamespace(data=d)
        manifest = dict(d["packages"])
        validate_resolution(c, manifest, [row(c, "libc"), row(c, "userapp")])
        for mutation in (
            "missing",
            "wrong-version",
            "wrong-abi",
            "public-native-collision",
        ):
            with self.subTest(mutation=mutation):
                rows = [row(c, "libc"), row(c, "userapp")]
                if mutation == "missing":
                    rows.pop()
                elif mutation == "wrong-version":
                    rows[0]["version"] = "2-r1"
                elif mutation == "wrong-abi":
                    rows[0]["name"] = "libc2026"
                else:
                    url = d["apk_repositories"]["public-packages"]["url"]
                    rows[0].update(
                        repositories=[url],
                        **{"download-url": url.rsplit("/", 1)[0] + "/libc-1-r1.apk"},
                    )
                with self.assertRaises(PolicyError):
                    validate_resolution(c, manifest, rows)
        bad = copy.deepcopy(d)
        del bad["package_origins"]["libc"]
        with self.assertRaises(PolicyError):
            validate_origin_catalog(bad)
        bad = copy.deepcopy(d)
        bad["package_origins"]["libc"]["repository"] = "public-packages"
        with self.assertRaises(PolicyError):
            validate_origin_catalog(bad)

    def test_signed_index_row_hash_is_not_canonical_json_hash(self):
        c = SimpleNamespace(data=data())
        entry = {
            "name": "libc",
            "version": "1-r1",
            "arch": "aarch64_cortex-a53",
            "hashes": "d" * 64,
        }
        validate_index_rows(c, "native", {"packages": [entry]}, {"libc": "1-r1"})
        entry["hashes"] = hashlib.sha256(json.dumps(entry).encode()).hexdigest()
        with self.assertRaises(PolicyError):
            validate_index_rows(c, "native", {"packages": [entry]}, {"libc": "1-r1"})

    def test_native_local_uri_equivalence_and_exact_cache_filename(self):
        c = SimpleNamespace(data=data())
        selected = row(c, "libc")
        selected["repositories"] = ["/builder/packages/packages.adb"]
        selected["download-url"] = "/builder/packages/libc-1-r1.apk"
        validate_resolution(c, {"libc": "1-r1"}, [selected])
        url = c.data["apk_repositories"]["public-packages"]["url"]
        expected = (
            "/builder/dl/APKINDEX."
            + hashlib.sha256(url.encode()).hexdigest()[:8]
            + ".tar.gz"
        )
        self.assertEqual(cache_index_path(url, "/builder/dl"), expected)


APK = Path(
    os.environ.get(
        "APK",
        "/home/valuxin/dev/owrt/asu-pbr-db-2026-10-21/task-tools/apk-3.0.5/build/src/apk",
    )
)


@unittest.skipUnless(
    APK.is_file() and shutil.which("openssl"),
    "actual trusted host APK and openssl unavailable",
)
class ActualAPKCandidates(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.native = self.root / "native"
        self.native.mkdir()
        self.public = self.root / "public"
        self.public.mkdir()
        self.keys = self.root / "keys"
        self.keys.mkdir()
        self.private = self.root / "private.pem"
        self.command(
            "openssl",
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-out",
            self.private,
        )
        self.command(
            "openssl",
            "pkey",
            "-in",
            self.private,
            "-pubout",
            "-out",
            self.keys / "public.pem",
        )
        self.package(self.native, "libc")
        self.package(self.public, "app-a", "libc !app-b")
        self.package(self.public, "app-b", "libc !app-a")
        self.package(self.public, "previously-unlisted", "libc")
        self.package(self.public, "libc", payload="foreign-same-name-version")
        for directory in (self.native, self.public):
            self.command(
                APK,
                "--no-network",
                "mkndx",
                "--allow-untrusted",
                "--sign",
                self.private,
                "--output",
                directory / "packages.adb",
                *directory.glob("*.apk"),
            )
        self.database = self.root / "root"
        for directory in ("lib/apk/db", "etc/apk"):
            (self.database / directory).mkdir(parents=True, exist_ok=True)
        for name in ("lib/apk/db/installed", "etc/apk/world"):
            (self.database / name).touch()
        self.repositories = self.root / "repositories"
        self.repositories.write_text(
            (self.native / "packages.adb").as_uri()
            + "\n@public "
            + (self.public / "packages.adb").as_uri()
            + "\n"
        )
        self.d = data()
        self.d["apk_repositories"] = {
            "native": {
                "url": (self.native / "packages.adb").as_uri(),
                "sha256": self.sha(self.native / "packages.adb"),
            },
            "public-packages": {
                "url": (self.public / "packages.adb").as_uri(),
                "sha256": self.sha(self.public / "packages.adb"),
            },
        }
        self.d["packages"] = {}
        self.d["package_identities"] = {}
        self.d["package_origins"] = {}
        for identifier, directory in (
            ("native", self.native),
            ("public-packages", self.public),
        ):
            obj = json.loads(
                self.command(
                    APK,
                    "--no-network",
                    "adbdump",
                    "--format",
                    "json",
                    directory / "packages.adb",
                ).stdout
            )
            for entry in obj["packages"]:
                name = entry["name"]
                if identifier != "native" and name == "libc":
                    continue
                self.d["packages"][name] = entry["version"]
                self.d["package_identities"][name] = {
                    "name": name,
                    "abi": "",
                    "version": entry["version"],
                    "tag": "" if identifier == "native" else "public",
                }
                self.d["package_origins"][name] = {
                    "repository": identifier,
                    "filename": name + "-" + entry["version"] + ".apk",
                    "identity_sha256": entry["hashes"],
                }
        self.c = SimpleNamespace(data=self.d)

    def command(self, *args):
        return subprocess.run(
            list(map(str, args)), check=True, capture_output=True, timeout=30
        )

    def sha(self, path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def package(self, directory, name, depends=None, payload=None):
        source = self.root / (directory.name + "-payload-" + name)
        source.mkdir()
        (source / name).write_text(payload or name)
        args = [
            APK,
            "--no-network",
            "mkpkg",
            "--info",
            "name:" + name,
            "--info",
            "version:1-r1",
            "--info",
            "arch:aarch64_cortex-a53",
            "--files",
            source,
            "--output",
            directory / (name + "-1-r1.apk"),
        ]
        if depends:
            args += ["--info", "depends:" + depends]
        self.command(*args)

    def query(self, names):
        base = [
            APK,
            "--root",
            self.database,
            "--arch",
            "aarch64_cortex-a53",
            "--no-network",
            "--keys-dir",
            self.keys,
            "--repositories-file",
            self.repositories,
        ]
        specs = ["libc=1-r1", *[name + "@public=1-r1" for name in names]]
        simulated = subprocess.run(
            list(
                map(
                    str,
                    [
                        *base,
                        "add",
                        "--simulate",
                        "--no-scripts",
                        "--no-commit-hooks",
                        "--usermode",
                        *specs,
                    ],
                )
            ),
            capture_output=True,
            timeout=30,
        )
        if simulated.returncode or simulated.stderr.strip():
            raise PolicyError("Actual APK simulator rejected requested set")
        args = [
            *base,
            "query",
            "--from",
            "repositories",
            "--recursive",
            "--format",
            "json",
            "--fields",
            "name,version,arch,depends,repositories,download-url",
            *specs,
        ]
        process = subprocess.run(list(map(str, args)), capture_output=True, timeout=30)
        if process.returncode or process.stderr.strip():
            raise PolicyError("Actual APK solver rejected requested set")
        rows = json.loads(process.stdout)
        manifest = {"libc": "1-r1", **{name: "1-r1" for name in names}}
        validate_resolution(self.c, manifest, rows)
        for identifier, directory in (
            ("native", self.native),
            ("public-packages", self.public),
        ):
            self.command(
                APK,
                "--no-network",
                "--keys-dir",
                self.keys,
                "verify",
                directory / "packages.adb",
            )
            obj = json.loads(
                self.command(
                    APK,
                    "--no-network",
                    "adbdump",
                    "--format",
                    "json",
                    directory / "packages.adb",
                ).stdout
            )
            validate_index_rows(self.c, identifier, obj, manifest)
        return rows

    def test_individual_candidates_preserved_but_combined_conflict_rejected(self):
        for name in ("app-a", "app-b", "previously-unlisted"):
            self.assertIn(name, {entry["name"] for entry in self.query([name])})
        with self.assertRaises(PolicyError):
            self.query(["app-a", "app-b"])

    def test_same_name_version_foreign_native_payload_origin_rejected(self):
        rows = self.query(["previously-unlisted"])
        native = next(entry for entry in rows if entry["name"] == "libc")
        native.update(
            repositories=[(self.public / "packages.adb").as_uri()],
            **{"download-url": (self.public / "libc-1-r1.apk").as_uri()},
        )
        with self.assertRaises(PolicyError):
            validate_resolution(
                self.c, {"libc": "1-r1", "previously-unlisted": "1-r1"}, rows
            )

    def test_actual_http_cache_identity_is_checked_beyond_short_filename_hash(self):
        import functools
        import http.server
        import threading

        class Handler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *_):
                pass

        server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), functools.partial(Handler, directory=str(self.public))
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        url = "http://127.0.0.1:" + str(server.server_port) + "/packages.adb"
        self.d["apk_repositories"]["public-packages"]["url"] = url
        self.repositories.write_text(
            (self.native / "packages.adb").as_uri() + "\n@public " + url + "\n"
        )
        cache = self.root / "cache"
        cache.mkdir()
        base = [
            APK,
            "--root",
            self.database,
            "--arch",
            "aarch64_cortex-a53",
            "--cache-packages",
            "--cache-dir",
            cache,
            "--keys-dir",
            self.keys,
            "--repositories-file",
            self.repositories,
        ]
        self.command(
            *base,
            "add",
            "--no-scripts",
            "--no-commit-hooks",
            "--usermode",
            "libc=1-r1",
            "previously-unlisted@public=1-r1",
        )
        result = self.command(
            *base,
            "query",
            "--from",
            "repositories",
            "--recursive",
            "--format",
            "json",
            "--fields",
            "name,version,arch,depends,repositories,download-url",
            "libc=1-r1",
            "previously-unlisted@public=1-r1",
        )
        rows = json.loads(result.stdout)
        self.assertFalse(result.stderr.strip(), result.stderr.decode())
        manifest = {"libc": "1-r1", "previously-unlisted": "1-r1"}
        self.assertEqual(validate_resolution(self.c, manifest, rows, str(cache)), {})
        # The repository-only query deliberately exposes the signed origin.
        # A system query can instead select cache bytes; those require a full
        # recomputed identity, never acceptance based on the short filename.
        result = self.command(
            *base,
            "--no-network",
            "query",
            "--from",
            "system",
            "--recursive",
            "--format",
            "json",
            "--fields",
            "name,version,arch,depends,repositories,download-url",
            "libc=1-r1",
            "previously-unlisted@public=1-r1",
        )
        self.assertFalse(result.stderr.strip(), result.stderr.decode())
        rows = json.loads(result.stdout)
        self.assertTrue(all("download-url" in item for item in rows), repr(rows))
        for item in rows:
            if item["name"] == "previously-unlisted":
                expected = (
                    str(cache)
                    + "/previously-unlisted-1-r1."
                    + self.d["package_origins"]["previously-unlisted"][
                        "identity_sha256"
                    ][:8]
                    + ".apk"
                )
                self.assertEqual(item["download-url"], Path(expected).name)
        cached = validate_resolution(self.c, manifest, rows, str(cache))
        self.assertIn("previously-unlisted", cached)
        rebuilt = self.root / "rebuilt.adb"

        def inspect():
            self.command(
                APK,
                "--no-network",
                "mkndx",
                "--hash",
                "sha256",
                "--allow-untrusted",
                "--output",
                rebuilt,
                *cached.values(),
            )
            obj = json.loads(
                self.command(
                    APK, "--no-network", "adbdump", "--format", "json", rebuilt
                ).stdout
            )
            validate_index_rows(
                self.c,
                "public-packages",
                obj,
                {name: manifest[name] for name in cached},
            )

        inspect()
        foreign = self.root / "foreign"
        foreign.mkdir()
        self.package(
            foreign,
            "previously-unlisted",
            payload="different signed-index identity, same name/version",
        )
        shutil.copyfile(
            foreign / "previously-unlisted-1-r1.apk", cached["previously-unlisted"]
        )
        with self.assertRaises(PolicyError):
            inspect()

    def test_actual_make_proof_reuses_root_cache_keys_and_preserves_main_makefile(self):
        import functools
        import http.server
        import io
        import tarfile
        import threading
        from asu.public_policy import verify_apk_resolution, NATIVE_INDEX
        from unittest.mock import patch, Mock

        fetched = []

        class Handler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                fetched.append(self.path)
                super().do_GET()

        server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), functools.partial(Handler, directory=str(self.public))
        )
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        url = "http://127.0.0.1:" + str(server.server_port) + "/packages.adb"
        self.d["apk_repositories"]["public-packages"]["url"] = url
        self.d["apk_repositories"]["native"]["url"] = NATIVE_INDEX
        self.repositories.write_text(
            (self.native / "packages.adb").as_uri() + "\n@public " + url + "\n"
        )
        cache = self.root / "dl"
        cache.mkdir()
        base = [
            str(APK),
            "--root",
            str(self.database),
            "--arch",
            "aarch64_cortex-a53",
            "--cache-dir",
            str(cache),
            "--keys-dir",
            str(self.keys),
            "--repositories-file",
            str(self.repositories),
        ]
        makefile = self.root / "Makefile"
        makefile.write_text(
            "DL_DIR := "
            + str(cache)
            + "\nTARGET_DIR := "
            + str(self.database)
            + "\nTMP_DIR := "
            + str(self.root / "tmp")
            + "\nBIN_DIR := "
            + str(self.root / "bin")
            + "\nAPK_KEYS := "
            + str(self.keys)
            + "\nAPK := "
            + " ".join(base)
            + "\n.PHONY: _check_keys\n_check_keys:\n\t@"
            + str(APK)
            + " --no-network --keys-dir "
            + str(self.keys)
            + " verify "
            + str(self.native / "packages.adb")
            + "\npackage_reload:\n\t@$(APK) add --initdb --usermode\n"
        )
        fixture = self
        mapping = {
            "/builder/staging_dir/host/bin/apk": str(APK),
            "/builder/packages": str(self.native),
            "/builder/dl": str(cache),
            "/builder/keys": str(self.keys),
            "/builder/root": str(self.database),
            "/builder/Makefile": str(makefile),
        }

        def actual(arg):
            for virtual, real in mapping.items():
                if arg == virtual or arg.startswith(virtual + "/"):
                    return real + arg[len(virtual) :]
            if arg.startswith("/builder/"):
                return str(fixture.root / arg.removeprefix("/builder/"))
            return arg

        class Container:
            def put_archive(self, _, content):
                with tarfile.open(fileobj=io.BytesIO(content)) as archive:
                    for member in archive:
                        target = fixture.root / member.name
                        target.write_bytes(
                            archive.extractfile(member)
                            .read()
                            .replace(b"/builder/Makefile", str(makefile).encode())
                        )
                return True

            def exec_run(self, command, **_):
                if command == ["df", "-P", "-B1", "/builder"]:
                    return 0, (
                        b"Filesystem 1B-blocks Used Available Capacity Mounted on\nfixture 214748364800 0 214748364800 0% /builder\n",
                        b"",
                    )
                result = subprocess.run(
                    [actual(arg) for arg in command],
                    cwd=fixture.root,
                    capture_output=True,
                    timeout=30,
                )
                output = result.stdout
                for virtual, real in sorted(
                    mapping.items(), key=lambda pair: len(pair[1]), reverse=True
                ):
                    output = output.replace(real.encode(), virtual.encode())
                return result.returncode, (output, result.stderr)

        def make_tar(files):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w") as archive:
                for name, content in files.items():
                    member = tarfile.TarInfo(name)
                    member.size = len(content)
                    archive.addfile(member, io.BytesIO(content))
            return stream.getvalue()

        before = makefile.read_bytes()
        proof = verify_apk_resolution(
            Container(),
            self.c,
            {"libc": "1-r1", "previously-unlisted": "1-r1"},
            "fixture",
            make_tar,
        )
        self.assertEqual(proof["packages"], 2)
        self.assertEqual(proof["root"], "/builder/root")
        self.assertEqual(proof["cache"], "/builder/dl")
        self.assertEqual(proof["simulation"], "passed")
        self.assertEqual(makefile.read_bytes(), before)
        self.assertFalse(any(path.endswith(".apk") for path in fetched))
        self.assertEqual((self.database / "lib/apk/db/installed").read_text(), "")
        self.assertGreater(size_budget(proof["selected_rows"])["installed_bytes"], 0)
        install = Mock()
        with (
            patch("asu.public_policy.MAX_INSTALLED", 1),
            self.assertRaises(PolicyError),
        ):
            admitted_apk_manifest(
                Container(),
                self.c,
                ["libc", "previously-unlisted"],
                "fixture",
                make_tar,
                self.root,
                lambda _: None,
                install,
            )
        install.assert_not_called()
        self.assertFalse(any(path.endswith(".apk") for path in fetched))
        events = []

        def installed_manifest():
            events.append("install")
            self.assertFalse(any(path.endswith(".apk") for path in fetched))
            self.command(
                *base,
                "add",
                "--no-scripts",
                "--no-commit-hooks",
                "--usermode",
                "libc=1-r1",
                "previously-unlisted@public=1-r1",
            )
            result = self.command(
                *base,
                "query",
                "--from",
                "installed",
                "--format",
                "json",
                "--fields",
                "name,version",
                "*",
            )
            return {row["name"]: row["version"] for row in json.loads(result.stdout)}

        with patch(
            "asu.public_policy.shutil.disk_usage",
            return_value=SimpleNamespace(free=100 * 1024**3),
        ):
            installed, accepted = admitted_apk_manifest(
                Container(),
                self.c,
                ["libc", "previously-unlisted"],
                "fixture",
                make_tar,
                self.root,
                lambda _: events.append("validate"),
                installed_manifest,
            )
        self.assertEqual(events, ["validate", "install"])
        self.assertEqual(installed, accepted["manifest"])
        self.assertTrue(any(path.endswith(".apk") for path in fetched))


if __name__ == "__main__":
    unittest.main()
