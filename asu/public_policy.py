"""Per-request APK compatibility and exact frozen index/origin proof."""

import hashlib
import json
from pathlib import PurePosixPath
import re
import shutil
from pathlib import Path
from urllib.parse import urlsplit

from asu.ax6000_policy import (
    NAME,
    digest,
    image_package_specs,
    protected_packages,
    require,
)

NATIVE_INDEX = "file:///builder/packages/packages.adb"
FIELDS = "name,version,arch,depends,repositories,download-url"
MAX_INSTALLED = 2 * 1024**3
MAX_ARCHIVES = 512 * 1024**2
FREE_RESERVE = 20 * 1024**3
QUERY_MAKEFILE = b"""include /builder/Makefile
.PHONY: asu-origin-context asu-origin-prepare asu-origin-proof
asu-origin-context:
	@printf '%s\\n' '$(abspath $(DL_DIR))' '$(abspath $(TARGET_DIR))' '$(abspath $(APK_KEYS))'
asu-origin-prepare:
	@$(MAKE) --no-print-directory -s -f /builder/Makefile _check_keys >/dev/null
	@rm -rf -- '$(TARGET_DIR)'
	@mkdir -p '$(TARGET_DIR)' '$(DL_DIR)' '$(TMP_DIR)' '$(BIN_DIR)'
	@$(MAKE) --no-print-directory -s -f /builder/Makefile package_reload >/dev/null
asu-origin-proof:
	@$(MAKE) --no-print-directory -s -f /builder/Makefile _check_keys >/dev/null
	@$(APK) add --simulate --no-scripts --no-commit-hooks --usermode $(ASU_ORIGIN_SPECS) >/dev/null
	@$(APK) query --from repositories --recursive --format json --fields name,version,arch,depends,repositories,download-url $(ASU_ORIGIN_SPECS)
"""


def local_uri(value):
    require(isinstance(value, str), "Invalid APK origin URI")
    if value.startswith("/builder/"):
        require(
            str(PurePosixPath(value)) == value
            and ".." not in PurePosixPath(value).parts,
            "Unsafe native APK origin",
        )
        return "file://" + value
    return value


def validate_origin_catalog(data):
    """Legacy metadata remains readable; actual APK builds require complete proof."""
    present = any(
        k in data for k in ("apk_repositories", "package_origins", "public_policy")
    )
    tagged = any(item.get("tag") for item in data["package_identities"].values())
    if data["package_manager"] != "apk":
        require(not present, "OPKG cannot select APK origins")
        return
    if not present and not tagged:
        return
    repos, origins = data.get("apk_repositories"), data.get("package_origins")
    require(
        isinstance(repos, dict) and 1 <= len(repos) <= 8,
        "Missing bounded APK repository identities",
    )
    require(
        isinstance(origins, dict) and set(origins) == set(data["package_identities"]),
        "Complete APK package origins required",
    )
    require(
        "native" in repos and repos["native"].get("url") == NATIVE_INDEX,
        "Native APK bank origin differs",
    )
    configured = {
        line.split()[-1]
        for line in data["repositories_conf"].splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    seen = set()
    for identifier, item in repos.items():
        require(
            isinstance(identifier, str)
            and NAME.fullmatch(identifier)
            and isinstance(item, dict)
            and set(item) == {"url", "sha256"}
            and digest(item["sha256"]),
            "Invalid frozen APK repository",
        )
        url = item["url"]
        require(
            isinstance(url, str) and url not in seen, "Ambiguous APK repository origin"
        )
        seen.add(url)
        if identifier != "native":
            parsed = urlsplit(url)
            require(
                (
                    identifier == "supplement"
                    or re.fullmatch(
                        r"public-(base|luci|packages|routing|telephony|video)",
                        identifier,
                    )
                )
                and url in configured
                and parsed.scheme == "https"
                and data["snapshot_sha256"] in parsed.path
                and parsed.path.endswith("/packages.adb"),
                "APK index is not an approved frozen repository",
            )
    pinned = protected_packages(data)
    for name, origin in origins.items():
        identity = data["package_identities"][name]
        require(
            isinstance(origin, dict)
            and set(origin) == {"repository", "filename", "identity_sha256"}
            and origin["repository"] in repos
            and digest(origin["identity_sha256"]),
            "Invalid APK package origin",
        )
        require(
            origin["filename"] == identity["name"] + "-" + identity["version"] + ".apk"
            and "/" not in origin["filename"],
            "APK filename differs from indexed identity",
        )
        public = origin["repository"].startswith("public-")
        require(
            public == bool(identity["tag"])
            and (not public or identity["tag"] == "public"),
            "APK origin tag differs",
        )
        require(
            name not in pinned or origin["repository"] == "native",
            "Protected native APK cannot change origin",
        )
    if tagged:
        policy = data.get("public_policy")
        require(
            isinstance(policy, dict)
            and set(policy) == {"mode", "distribution", "tag"}
            and policy["mode"] in ("candidates", "validated-subset")
            and policy["distribution"] in ("immortalwrt", "openwrt")
            and policy["tag"] == "public",
            "Missing public APK candidate/subset policy",
        )
    else:
        require(
            "public_policy" not in data, "Public APK policy has no public identities"
        )


def cache_index_path(url, cache):
    if url == NATIVE_INDEX:
        return "/builder/packages/packages.adb"
    require(
        cache.startswith("/builder/")
        and str(PurePosixPath(cache)) == cache
        and ".." not in PurePosixPath(cache).parts,
        "APK cache path escapes builder",
    )
    # Exact pinned apk-tools 3.0.5 apk_repo_index_cache_url, not a guessed glob.
    return (
        cache + "/APKINDEX." + hashlib.sha256(url.encode()).hexdigest()[:8] + ".tar.gz"
    )


def validate_index_rows(catalog, repository, obj, manifest):
    require(
        isinstance(obj, dict)
        and isinstance(obj.get("packages"), list)
        and 0 < len(obj["packages"]) <= 50000
        and obj.get("pkgname-spec", "${name}-${version}.apk")
        == "${name}-${version}.apk",
        "Invalid frozen APK index rows",
    )
    expected = {
        catalog.data["package_identities"][name]["name"]: name
        for name in manifest
        if catalog.data["package_origins"][name]["repository"] == repository
    }
    found = set()
    selected = {}
    for row in obj["packages"]:
        require(isinstance(row, dict), "Invalid signed index package row")
        name = row.get("name")
        if name not in expected:
            continue
        canonical = expected[name]
        require(name not in found, "Ambiguous signed APK identity")
        found.add(name)
        origin = catalog.data["package_origins"][canonical]
        require(
            row.get("version") == manifest[canonical]
            and row.get("arch") in ("aarch64_cortex-a53", "noarch")
            and row.get("hashes") == origin["identity_sha256"],
            "Signed APK row payload/version/architecture differs",
        )
        require(
            origin["filename"] == name + "-" + row["version"] + ".apk",
            "Signed APK filename differs",
        )
        selected[canonical] = row
    require(found == set(expected), "Frozen index omitted an approved APK identity")
    return selected


def size_budget(rows):
    installed, archives = 0, 0
    for row in rows.values():
        unpacked, archive = row.get("installed-size"), row.get("file-size")
        require(
            type(unpacked) is int
            and unpacked >= 0
            and type(archive) is int
            and archive > 0,
            "Signed APK row omits resource sizes",
        )
        installed += unpacked
        archives += archive
    require(
        installed <= MAX_INSTALLED and archives <= MAX_ARCHIVES,
        "Selected APK closure exceeds build resource budget",
    )
    return {"installed_bytes": installed, "archive_bytes": archives}


def require_free_space(public_path, budget):
    """Reserve the host filesystem used for copied, validated output."""
    path = Path(public_path)
    while not path.exists():
        path = path.parent
    projected = 2 * budget["installed_bytes"] + 2 * budget["archive_bytes"] + 1024**3
    require(
        shutil.disk_usage(path).free >= FREE_RESERVE + projected,
        "Insufficient host disk reserve for selected firmware packages",
    )
    return projected


def require_builder_free_space(container, budget):
    """Docker data-root may use a different filesystem from host public state."""
    output = (
        _run(container, ["df", "-P", "-B1", "/builder"], 4096).decode().splitlines()
    )
    require(
        len(output) == 2 and len(output[1].split()) >= 6,
        "Could not inspect builder filesystem reserve",
    )
    try:
        available = int(output[1].split()[3])
    except ValueError as error:
        raise ValueError("Invalid builder filesystem capacity") from error
    projected = 2 * budget["installed_bytes"] + 2 * budget["archive_bytes"] + 1024**3
    require(
        available >= FREE_RESERVE + projected,
        "Insufficient builder disk reserve for selected firmware packages",
    )
    return projected


def resolved_manifest(catalog, requested, rows):
    reverse = {
        item["name"]: base for base, item in catalog.data["package_identities"].items()
    }
    require(
        isinstance(rows, list) and rows and len(rows) <= 50000,
        "Empty or oversized APK solver closure",
    )
    manifest = {}
    for row in rows:
        require(
            isinstance(row, dict) and row.get("name") in reverse,
            "APK solver selected an unlisted identity",
        )
        base = reverse[row["name"]]
        require(
            base not in manifest
            and row.get("version") == catalog.data["packages"][base],
            "APK solver changed an approved identity/version",
        )
        manifest[base] = row["version"]
    require(
        set(requested) <= manifest.keys(),
        "APK solver silently omitted a requested package",
    )
    return manifest


def admitted_apk_manifest(
    container,
    catalog,
    requested,
    profile,
    make_tar,
    public_path,
    validate_closure,
    install_manifest,
):
    """No package payload is downloaded/unpacked before bounded metadata admission."""
    proof = verify_apk_resolution(container, catalog, requested, profile, make_tar)
    validate_closure(proof["manifest"])
    budget = size_budget(proof.pop("selected_rows"))
    proof["budget"] = budget
    proof["projected_staging_bytes"] = require_free_space(public_path, budget)
    require_builder_free_space(container, budget)
    actual = install_manifest()
    require(
        actual == proof["manifest"],
        "Installed APK manifest differs from admitted metadata closure",
    )
    return actual, proof


def validate_resolution(catalog, manifest, rows, cache=None):
    require(
        isinstance(rows, list) and rows and len(rows) <= 50000,
        "Empty or oversized APK solver closure",
    )
    actual = {
        catalog.data["package_identities"][name]["name"]: name for name in manifest
    }
    seen = set()
    cached = {}
    for row in rows:
        require(
            isinstance(row, dict)
            and row.get("name") in actual
            and row["name"] not in seen,
            "APK solver omitted, duplicated or changed an actual identity",
        )
        name = row["name"]
        seen.add(name)
        canonical = actual[name]
        require(
            row.get("version") == manifest[canonical]
            and row.get("arch") in ("aarch64_cortex-a53", "noarch"),
            "APK solver changed version/ABI/architecture",
        )
        origin = catalog.data["package_origins"][canonical]
        repository = catalog.data["apk_repositories"][origin["repository"]]["url"]
        require(
            isinstance(row.get("repositories"), list)
            and repository
            in {
                local_uri(url)
                for url in row["repositories"]
                if url != "lib/apk/db/installed"
            },
            "APK solver selected an unapproved repository",
        )
        expected = repository.rsplit("/", 1)[0] + "/" + origin["filename"]
        selected = row.get("download-url")
        cache_path = (
            (
                cache
                + "/"
                + origin["filename"][:-4]
                + "."
                + origin["identity_sha256"][:8]
                + ".apk"
            )
            if cache
            else None
        )
        if cache_path and selected in (
            cache_path,
            "file://" + cache_path,
            PurePosixPath(cache_path).name,
        ):
            cached[canonical] = cache_path
        else:
            require(
                local_uri(selected) == expected,
                "APK solver selected an unapproved download origin",
            )
    require(seen == set(actual), "APK solver silently omitted requested packages")
    return cached


def _run(container, command, limit=64 * 1024**2):
    status, streams = container.exec_run(command, demux=True, user="1000:1000")
    output, errors = streams
    output, errors = output or b"", errors or b""
    require(
        status == 0 and not errors.strip() and len(output) <= limit,
        "Actual APK compatibility/origin proof failed",
    )
    return output


def verify_apk_resolution(container, catalog, requested, profile, make_tar):
    """Use the immutable IB's own make variables, signed cache and exact tools."""
    require(
        "package_origins" in catalog.data and "apk_repositories" in catalog.data,
        "APK catalog requires re-promotion with complete origin evidence",
    )
    before = _run(container, ["sha256sum", "/builder/Makefile"], 4096)
    require(
        container.put_archive(
            "/builder/", make_tar({".asu-origin.mk": QUERY_MAKEFILE})
        ),
        "Could not inject trusted origin target",
    )
    command = ["make", "--no-print-directory", "-s", "-f", ".asu-origin.mk"]
    context = (
        _run(
            container, [*command, "asu-origin-context", "USER_PROFILE=" + profile], 4096
        )
        .decode()
        .splitlines()
    )
    require(len(context) == 3, "Unexpected ImageBuilder APK context")
    cache, root, keys = context
    require(
        all(
            value.startswith("/builder/")
            and str(PurePosixPath(value)) == value
            and ".." not in PurePosixPath(value).parts
            for value in context
        ),
        "ImageBuilder APK context escapes builder",
    )
    protected = ["/builder/packages", cache, keys]
    require(
        all(
            root != path
            and not PurePosixPath(path).is_relative_to(root)
            and not PurePosixPath(root).is_relative_to(path)
            for path in protected
        ),
        "ImageBuilder target root overlaps immutable/cache files",
    )
    require_builder_free_space(container, {"installed_bytes": 0, "archive_bytes": 0})
    _run(
        container, [*command, "asu-origin-prepare", "USER_PROFILE=" + profile], 1024**2
    )
    binary = "/builder/staging_dir/host/bin/apk"
    indexes = {}
    objects = {}
    for identifier in sorted(catalog.data["apk_repositories"]):
        record = catalog.data["apk_repositories"][identifier]
        path = cache_index_path(record["url"], cache)
        checksum = _run(container, ["sha256sum", path], 4096).decode().split()
        require(
            checksum and checksum[0] == record["sha256"],
            "Actual cached signed APK index bytes changed",
        )
        _run(
            container,
            [binary, "--no-network", "--keys-dir", keys, "verify", path],
            4096,
        )
        obj = json.loads(
            _run(
                container, [binary, "--no-network", "adbdump", "--format", "json", path]
            )
        )
        objects[identifier] = obj
        indexes[identifier] = record["sha256"]
    specs = image_package_specs(catalog, sorted(requested))
    output = _run(
        container,
        [
            *command,
            "asu-origin-proof",
            "USER_PROFILE=" + profile,
            "ASU_ORIGIN_SPECS=" + " ".join(specs),
        ],
    )
    rows = json.loads(output)
    manifest = resolved_manifest(catalog, requested, rows)
    cached = validate_resolution(catalog, manifest, rows, cache)
    selected_rows = {}
    for identifier, obj in objects.items():
        selected_rows.update(validate_index_rows(catalog, identifier, obj, manifest))
    if cached:
        paths = [cached[name] for name in sorted(cached)]
        # A cached download URL is not origin evidence by itself. Recompute the
        # complete native SHA256 ADB identity from actual APK bytes, not its
        # eight-character cache-name prefix or an unrelated JSON projection.
        _run(
            container,
            [binary, "--no-network", "--allow-untrusted", "verify", *paths],
            1024**2,
        )
        rebuilt = "/builder/.asu-cached-payloads.adb"
        _run(
            container,
            [
                binary,
                "--no-network",
                "mkndx",
                "--hash",
                "sha256",
                "--allow-untrusted",
                "--output",
                rebuilt,
                *paths,
            ],
            1024**2,
        )
        obj = json.loads(
            _run(
                container,
                [binary, "--no-network", "adbdump", "--format", "json", rebuilt],
            )
        )
        cached_manifest = {name: manifest[name] for name in cached}
        for identifier in {
            catalog.data["package_origins"][name]["repository"] for name in cached
        }:
            validate_index_rows(catalog, identifier, obj, cached_manifest)
    require(
        _run(container, ["sha256sum", "/builder/Makefile"], 4096) == before,
        "Trusted query changed native ImageBuilder Makefile",
    )
    for identifier, expected in indexes.items():
        path = cache_index_path(
            catalog.data["apk_repositories"][identifier]["url"], cache
        )
        checksum = _run(container, ["sha256sum", path], 4096).decode().split()
        require(
            checksum and checksum[0] == expected,
            "APK proof changed its frozen index bytes",
        )
    return {
        "packages": len(rows),
        "manifest": manifest,
        "selected_rows": selected_rows,
        "indexes": indexes,
        "cached_payloads": len(cached),
        "root": root,
        "cache": cache,
        "simulation": "passed",
    }
