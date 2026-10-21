"""Fail-closed policy for operator-promoted AX6000 generations.

This module has no engine/network/dependency imports. Catalogs are trusted only
when their complete bytes match the independently configured promotion digest.
"""

import hashlib
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

COHORTS = {"66": "6.6.", "612-recommended": "6.12.", "612-latest": "6.12."}
PROFILES = {
    "xiaomi_redmi-router-ax6000-" + x for x in ("stock", "mtkuboot", "ubootmod")
}
SHA = re.compile(r"[0-9a-f]{64}")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9+_.-]{0,127}")
ABI_SUFFIX = re.compile(r"-?[A-Za-z0-9][A-Za-z0-9+_.-]{0,127}")
MAX_CATALOG = 8 * 1024**2
MAX_PACKAGES = 2048


class PolicyError(ValueError):
    pass


def require(value, message):
    if not value:
        raise PolicyError(message)


def digest(value):
    return isinstance(value, str) and SHA.fullmatch(value) is not None


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


@dataclass(frozen=True)
class Catalog:
    data: dict
    sha256: str

    @classmethod
    def load(cls, path, expected_sha256, cohort):
        require(
            cohort in COHORTS and digest(expected_sha256),
            "Missing approved cohort/catalog digest",
        )
        p = Path(path)
        require(
            p.is_file() and not p.is_symlink() and p.stat().st_size <= MAX_CATALOG,
            "Catalog must be a bounded regular file",
        )
        raw = p.read_bytes()
        require(
            hashlib.sha256(raw).hexdigest() == expected_sha256, "Catalog digest changed"
        )
        try:
            data = json.loads(raw, object_pairs_hook=_unique_object)
        except (ValueError, TypeError) as e:
            raise PolicyError("Invalid catalog JSON") from e
        _validate_catalog(data, cohort)
        return cls(data, expected_sha256)

    @property
    def identity(self):
        d = self.data
        return {
            "schema_version": 1,
            "cohort": d["cohort"],
            "package_manager": d["package_manager"],
            "seed": d["seed"],
            "build_id": d["build_id"],
            "catalog_sha256": self.sha256,
            "snapshot_sha256": d["snapshot_sha256"],
            "kernel_version": d["firmware"]["kernel_version"],
        }

    @property
    def version(self):
        return self.data["firmware"]["version_number"]

    def normalize_profile(self, profile):
        require(isinstance(profile, str), "Missing layout profile")
        profile = profile.replace(",", "_")
        require(
            profile in self.data["profiles"], "Layout is not enabled for this cohort"
        )
        return profile


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate catalog key")
        result[key] = value
    return result


def _validate_catalog(d, cohort):
    require(
        isinstance(d, dict)
        and d.get("schema_version") == 1
        and d.get("cohort") == cohort,
        "Wrong catalog schema/cohort",
    )
    require(
        isinstance(d.get("build_id"), str) and NAME.fullmatch(d["build_id"]),
        "Invalid build ID",
    )
    require(
        isinstance(d.get("source_commit"), str)
        and re.fullmatch("[0-9a-f]{40}", d["source_commit"]),
        "Invalid source commit",
    )
    require(
        digest(d.get("seed")) and digest(d.get("snapshot_sha256")),
        "Invalid generation/snapshot identity",
    )
    promotion = d.get("promotion", {})
    require(
        promotion.get("verified") is True
        and all(
            digest(promotion.get(x))
            for x in (
                "native_evidence_sha256",
                "imagebuilder_evidence_sha256",
                "feed_evidence_sha256",
            )
        ),
        "Catalog has not passed native/ImageBuilder/feed promotion",
    )
    manager = d.get("package_manager")
    require(
        manager == ("opkg" if cohort == "66" else "apk"),
        "Wrong package manager for cohort",
    )
    from asu.overlay_policy import decode_overlay, validate_apk_roots

    decode_overlay(d.get("rootfs_overlay"), manager)
    validate_apk_roots(d, manager)
    ib = d.get("imagebuilder", {})
    require(digest(ib.get("archive_sha256")), "Missing verified ImageBuilder archive")
    image = ib.get("image", "")
    require(
        isinstance(image, str)
        and (
            re.fullmatch("sha256:[0-9a-f]{64}", image)
            or re.fullmatch(r"[a-z0-9./_-]+@sha256:[0-9a-f]{64}", image)
        ),
        "ImageBuilder must use immutable image ID/digest",
    )
    f = d.get("firmware", {})
    require(
        f.get("target") == "mediatek/filogic"
        and f.get("architecture") == "aarch64_cortex-a53",
        "Foreign firmware target/architecture",
    )
    require(
        isinstance(f.get("version_number"), str)
        and re.fullmatch(r"[\w.+-]{1,100}", f["version_number"]),
        "Invalid firmware version",
    )
    require(
        isinstance(f.get("version_code"), str)
        and re.fullmatch(r"r[\w.+-]{1,100}", f["version_code"]),
        "Invalid firmware revision",
    )
    require(
        isinstance(f.get("kernel_version"), str)
        and re.fullmatch(r"\d+\.\d+\.\d+~[0-9a-f]{32}-r\d+", f["kernel_version"])
        and f["kernel_version"].startswith(COHORTS[cohort]),
        "Wrong kernel ABI/cohort",
    )
    packages = d.get("packages", {})
    require(
        isinstance(packages, dict)
        and 1 <= len(packages) <= 50000
        and all(
            NAME.fullmatch(k)
            and isinstance(v, str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+_.~:-]{0,149}", v)
            for k, v in packages.items()
        ),
        "Invalid package inventory",
    )
    require(
        packages.get("kernel") == f["kernel_version"], "Package bank kernel ABI differs"
    )
    profiles = d.get("profiles", {})
    require(
        isinstance(profiles, dict) and profiles and set(profiles) <= PROFILES,
        "Invalid profile inventory",
    )
    if cohort == "66":
        require(
            set(profiles) == {"xiaomi_redmi-router-ax6000-stock"},
            "6.6 supports stock layout only",
        )
    for name, profile in profiles.items():
        require(
            profile.get("supported_devices") == [name.replace("xiaomi_", "xiaomi,")],
            "Wrong supported device/layout",
        )
        for field in ("mandatory_packages", "default_packages"):
            values = profile.get(field)
            require(
                isinstance(values, list)
                and values
                and len(values) == len(set(values))
                and all(isinstance(p, str) and p in packages for p in values),
                "Invalid profile packages",
            )
        mandatory = set(profile["mandatory_packages"])
        require(
            {
                "base-files",
                "busybox",
                "kernel",
                "libc",
                "kmod-mt_wifi",
                "kmod-mediatek_hnat",
                "luci-app-attendedsysupgrade",
            }
            <= mandatory,
            "Missing mandatory core/vendor/ASU packages",
        )
        if manager == "opkg":
            require(
                "opkg" in mandatory and not any(x.startswith("apk") for x in mandatory),
                "Wrong mandatory package manager",
            )
        else:
            require(
                len(mandatory & {"apk", "apk-mbedtls", "apk-openssl"}) == 1
                and "opkg" not in mandatory,
                "Wrong mandatory package manager",
            )
        require(
            "tailscale" not in mandatory
            and "tailscale" not in profile["default_packages"],
            "Tailscale is personalized only",
        )
        require(
            isinstance(profile.get("max_image_size"), int)
            and 0 < profile["max_image_size"] <= 128 * 1024**2,
            "Invalid partition bound",
        )
    repositories = d.get("repositories_conf", "")
    require(
        isinstance(repositories, str) and len(repositories) < 32768,
        "Invalid repositories",
    )
    sources = []
    repository_tags = set()
    for line in repositories.splitlines():
        line = line.strip()
        if (
            not line
            or line.startswith("#")
            or (manager == "opkg" and line == "option check_signature")
        ):
            continue
        parts = line.split()
        if manager == "opkg":
            require(
                len(parts) == 3 and parts[0] == "src/gz" and NAME.fullmatch(parts[1]),
                "Only immutable signed HTTPS feeds are allowed",
            )
            source = parts[2]
        else:
            require(len(parts) in (1, 2), "Invalid APK repository line")
            if len(parts) == 2:
                require(
                    parts[0].startswith("@") and NAME.fullmatch(parts[0][1:]),
                    "Invalid APK repository tag",
                )
                repository_tags.add(parts[0][1:])
            source = parts[-1]
        url = urlsplit(source)
        require(
            url.scheme == "https"
            and url.hostname
            and not url.username
            and not url.password
            and not url.query
            and not url.fragment
            and d["snapshot_sha256"] in url.path,
            "Repository is not bound to approved snapshot",
        )
        sources.append(source)
    require(
        sources
        and (manager == "apk" or "option check_signature" in repositories.splitlines()),
        "Missing signature-checked snapshot",
    )
    identities = d.get("package_identities", {})
    require(isinstance(identities, dict), "Invalid package identities")
    require(
        set(identities) == set(packages), "Complete indexed package identities required"
    )
    protected = protected_packages(d)
    actual_names = set()
    for canonical_name, identity in identities.items():
        require(
            canonical_name in packages and isinstance(identity, dict),
            "Unknown package identity",
        )
        name, abi, version, tag = (
            identity.get(k) for k in ("name", "abi", "version", "tag")
        )
        require(
            isinstance(name, str)
            and NAME.fullmatch(name)
            and isinstance(abi, str)
            and (not abi or ABI_SUFFIX.fullmatch(abi))
            and name == canonical_name + abi
            and version == packages[canonical_name]
            and isinstance(tag, str),
            "Invalid actual package identity",
        )
        require(name not in actual_names, "Ambiguous actual package identity")
        actual_names.add(name)
        require(
            not tag
            or (
                manager == "apk"
                and tag in repository_tags
                and canonical_name not in protected
            ),
            "Protected or unknown repository tag",
        )
    specs = d.get("package_specs", {})
    require(
        isinstance(specs, dict) and len(specs) <= len(packages),
        "Invalid package specifications",
    )
    extra_protected = d.get("protected_packages", [])
    require(
        isinstance(extra_protected, list)
        and all(p in packages for p in extra_protected),
        "Invalid protected package list",
    )
    for name, spec in specs.items():
        require(
            manager == "apk"
            and name in identities
            and spec == _identity_spec(identities[name]),
            "Package specification differs from approved indexed identity",
        )
    require(
        isinstance(d.get("repository_keys"), list)
        and 1 <= len(d["repository_keys"]) <= 8
        and all(isinstance(k, str) and len(k) < 8192 for k in d["repository_keys"]),
        "Missing repository public keys",
    )
    from asu.public_policy import validate_origin_catalog

    validate_origin_catalog(d)


def protected_packages(data):
    return (
        set(data.get("protected_packages", []))
        | {
            p
            for profile in data["profiles"].values()
            for p in profile["mandatory_packages"]
        }
        | {p for p in data["packages"] if p.startswith("kmod-")}
    )


def _identity_spec(identity):
    return (
        identity["name"]
        + ("@" + identity["tag"] if identity["tag"] else "")
        + "="
        + identity["version"]
    )


def image_package_specs(catalog, packages):
    """Only verified actual APK identities can add repository tags/version pins."""
    result = []
    for name in packages:
        if name.startswith("-"):
            result.append(name)
        elif catalog.data["package_manager"] == "opkg":
            result.append(catalog.data["package_identities"][name]["name"])
        else:
            result.append(_identity_spec(catalog.data["package_identities"][name]))
    return result


def normalize_emitted_manifest(catalog, manifest):
    reverse = {
        identity["name"]: name
        for name, identity in catalog.data.get("package_identities", {}).items()
    }
    result = {}
    for name, version in manifest.items():
        require(name in reverse, "Unapproved actual package identity: " + name)
        canonical_name = reverse[name]
        require(canonical_name not in result, "Duplicate normalized emitted package")
        result[canonical_name] = version
    return result


def validate_request(catalog, request):
    require(isinstance(request, dict), "Invalid request")
    d = catalog.data
    require(request.get("distro", "openwrt") == "openwrt", "Unsupported API distro")
    require(
        request.get("version") == catalog.version
        and request.get("target") == "mediatek/filogic",
        "Wrong target version/cohort",
    )
    require(
        request.get("ax6000") == catalog.identity,
        "Wrong or stale cohort/generation/snapshot",
    )
    for key in ("defaults", "repositories", "repository_keys", "rootfs_size_mb"):
        require(not request.get(key), "Client " + key + " override is disabled")
    require(
        request.get("repositories_mode", "replace") == "replace",
        "Repository override is disabled",
    )
    require(
        request.get("filesystem") in (None, "squashfs"), "Only squashfs is supported"
    )
    revision = request.get("version_code", "")
    require(
        not revision or revision == d["firmware"]["version_code"],
        "Wrong target revision",
    )
    installed_manager = request.get("installed_package_manager")
    if installed_manager is None and d["cohort"] == "66":
        installed_manager = "opkg"
    require(
        installed_manager == d["package_manager"],
        "Cross-package-manager sysupgrade is disabled",
    )
    profile = catalog.normalize_profile(request.get("profile"))
    names = request.get("packages", [])
    versions = request.get("packages_versions", {})
    require(
        isinstance(names, list)
        and isinstance(versions, dict)
        and len(names) <= MAX_PACKAGES
        and len(versions) <= MAX_PACKAGES,
        "Package request exceeds limit",
    )
    installed = request.get("installed_packages", [])
    require(
        isinstance(installed, list)
        and len(installed) <= MAX_PACKAGES
        and all(isinstance(x, str) and NAME.fullmatch(x) for x in installed),
        "Invalid installed package list",
    )
    require(
        all(isinstance(x, str) and NAME.fullmatch(x) for x in names),
        "Unknown or unsafe package",
    )
    require(
        all(name in d["packages"] for name in installed),
        "Installed package unavailable in approved snapshot",
    )
    names = set(names) | set(versions)
    for name in names | set(installed):
        require(
            isinstance(name, str) and NAME.fullmatch(name) and name in d["packages"],
            "Unknown or unsafe package",
        )
        require(
            not name.startswith(("kmod-mt76", "kmod-mt7915", "kmod-mt7986-firmware"))
            and not (d["package_manager"] == "opkg" and name.startswith("apk"))
            and not (d["package_manager"] == "apk" and name == "opkg"),
            "Foreign package manager/Wi-Fi stack",
        )
    for name, version in versions.items():
        require(
            version == d["packages"].get(name),
            "Requested target package version is unavailable",
        )
    require(
        "tailscale" not in names or "tailscale" in installed,
        "Tailscale must already be installed",
    )
    packages = sorted(
        names | set(installed) | set(d["profiles"][profile]["mandatory_packages"])
    )
    require(
        len(packages) <= MAX_PACKAGES,
        "Combined installed/requested package set exceeds limit",
    )
    return {
        **request,
        "profile": profile,
        "packages": packages,
        "installed_packages": sorted(set(installed)),
        "packages_versions": versions,
        "version_code": d["firmware"]["version_code"],
        "diff_packages": True,
        "ax6000": catalog.identity,
    }


def cache_hash(catalog, request):
    normalized = {k: v for k, v in request.items() if k != "client"}
    normalized["packages"] = sorted(set(normalized.get("packages", [])))
    return hashlib.sha256(
        canonical({"catalog": catalog.identity, "request": normalized})
    ).hexdigest()


def get_catalog():
    """Deployment selects one catalog per API process; never mutate globals per request."""
    import os

    path = os.environ.get("ASU_AX6000_CATALOG")
    if not path:
        return None
    return _cached_catalog(
        path,
        os.environ.get("ASU_AX6000_CATALOG_SHA256", ""),
        os.environ.get("ASU_AX6000_COHORT", ""),
    )


_cached_catalog = lru_cache(maxsize=3)(Catalog.load)


def validate_manifest(catalog, request, manifest):
    """The assembled closure must use only the exact approved package versions."""
    require(isinstance(manifest, dict) and manifest, "Empty ImageBuilder manifest")
    expected = catalog.data["packages"]
    require(
        set(request["packages"]) <= set(manifest),
        "ImageBuilder dropped requested packages",
    )
    require(
        set(request.get("installed_packages", [])) <= set(manifest),
        "ImageBuilder dropped installed packages",
    )
    for name, version in manifest.items():
        require(
            name in expected and expected[name] == version,
            "Unapproved package/version in ImageBuilder closure: " + name,
        )
    require(
        manifest.get("kernel") == catalog.data["firmware"]["kernel_version"],
        "ImageBuilder kernel ABI differs",
    )
    require(
        ("tailscale" in manifest) == ("tailscale" in request["packages"]),
        "Tailscale image policy differs",
    )
    require(
        not any(
            p.startswith(("kmod-mt76", "kmod-mt7915", "kmod-mt7986-firmware"))
            for p in manifest
        ),
        "Foreign Wi-Fi stack in image manifest",
    )
    manager = catalog.data["package_manager"]
    require(
        not (manager == "apk" and "opkg" in manifest)
        and not (manager == "opkg" and any(p.startswith("apk") for p in manifest)),
        "Foreign package manager in image manifest",
    )
