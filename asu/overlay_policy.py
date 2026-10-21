"""Preserve promoted native policy files and verify the actual SquashFS bytes."""

import base64
import hashlib
import json
import re
import io
import tarfile
import zlib
from pathlib import Path

from asu.ax6000_policy import canonical, require, NAME

COMMON = {
    "etc/asu-cohort.json": 0o644,
    "etc/uci-defaults/99-ax6000-asu": 0o755,
    "usr/sbin/ax6000-install-feed": 0o755,
}
APK = {
    "etc/apk/repositories.d/distfeeds.list": 0o644,
    "etc/apk/repositories.d/customfeeds.list": 0o644,
    "etc/apk/keys/repository-apk.pem": 0o644,
    "etc/ax6000/repository.pub": 0o644,
}
MAX_FILE = 64 * 1024


def static_fit_root(path):
    """Read native ubootmod external-static-with-rootfs, allowing fwtool trailer.

    FDT parsing is vendored from the independently reviewed native recipe.
    Resolve explicit configuration references and verify all payload ranges and
    CRC32/SHA1 hashes; never scan for a SquashFS magic or guess a byte offset.
    """
    from asu.fit_payload import read_fdt, text, stringlist, cell

    path = Path(path)
    size = path.stat().st_size
    require(4096 <= size <= 128 * 1024**2, "FIT image exceeds byte limit")
    tree = read_fdt(path, 64 * 1024)
    require(tree.total == 4096, "Native static FIT header size differs")
    require(
        text(tree.nodes.get("/configurations", {}).get("default", b"")) == "config-1",
        "Unexpected FIT default configuration",
    )
    config = tree.nodes.get("/configurations/config-1", {})
    require(
        text(config.get("kernel", b"")) == "kernel-1"
        and text(config.get("fdt", b"")) == "fdt-1"
        and stringlist(config.get("loadables", b"")) == ["rootfs-1"]
        and "ramdisk" not in config,
        "Unexpected FIT image references",
    )
    require(
        tree.children("/configurations") == ["/configurations/config-1"]
        and set(tree.children("/images"))
        == {"/images/kernel-1", "/images/fdt-1", "/images/rootfs-1"},
        "Unexpected native FIT nodes",
    )
    next_position = 4096
    root = None
    with path.open("rb") as stream:
        for name, kind, compression, limit in (
            ("kernel-1", "kernel", "gzip", 32 * 1024**2),
            ("fdt-1", "flat_dt", "none", 256 * 1024),
            ("rootfs-1", "filesystem", "none", 0x7A80000),
        ):
            node = "/images/" + name
            props = tree.nodes[node]
            require(
                text(props.get("type", b"")) == kind
                and text(props.get("arch", b"")) == "arm64"
                and text(props.get("compression", b"")) == compression,
                "FIT payload type differs",
            )
            require(
                set(props) & {"data", "data-position", "data-offset", "data-size"}
                == {"data-position", "data-size"},
                "FIT payload position is not static",
            )
            start, length = cell(props["data-position"]), cell(props["data-size"])
            require(
                start == next_position
                and 0 < length <= limit
                and start + length <= size,
                "FIT payload range differs",
            )
            stream.seek(start)
            content = stream.read(length)
            require(len(content) == length, "Truncated FIT payload")
            hashes = tree.children(node)
            require(
                set(hashes) == {node + "/hash-1", node + "/hash-2"},
                "Unexpected FIT hash nodes",
            )
            expected = {}
            for child in hashes:
                hash_props = tree.nodes[child]
                algo = text(hash_props.get("algo", b""))
                require(
                    algo in ("crc32", "sha1") and algo not in expected,
                    "Invalid FIT payload hash",
                )
                expected[algo] = bytes(hash_props.get("value", b""))
            require(
                expected
                == {
                    "crc32": (zlib.crc32(content) & 0xFFFFFFFF).to_bytes(4, "big"),
                    "sha1": hashlib.sha1(content).digest(),
                },
                "FIT payload checksum differs",
            )
            padding = (-(start + length)) % 4096
            require(not any(stream.read(padding)), "Nonzero FIT payload padding")
            next_position = (start + length + 4095) & ~4095
            if name == "rootfs-1":
                root = content
    require(
        root is not None and next_position <= size, "FIT filesystem payload missing"
    )
    return root


def validate_apk_roots(data, manager):
    roots = data.get("apk_protected_roots", [])
    require(isinstance(roots, list), "Invalid APK protected roots")
    if manager == "opkg":
        require(not roots, "OPKG catalog cannot select APK protected roots")
        return
    require(
        1 <= len(roots) <= 10000
        and all(isinstance(p, str) and NAME.fullmatch(p) for p in roots),
        "Missing attested APK protected roots",
    )
    require(
        roots == sorted(set(roots)), "APK protected roots must be unique and sorted"
    )


def decode_overlay(data, manager):
    require(
        isinstance(data, dict) and 1 <= len(data) <= 32, "Missing native rootfs overlay"
    )
    expected = {
        **COMMON,
        **(APK if manager == "apk" else {"etc/opkg/distfeeds.conf": 0o644}),
    }
    if manager == "opkg":
        keys = [
            p
            for p in data
            if isinstance(p, str) and re.fullmatch(r"etc/opkg/keys/[0-9a-f]{16}", p)
        ]
        require(len(keys) == 1, "Exactly one promoted OPKG repository key required")
        expected[keys[0]] = 0o644
    require(
        set(data) == set(expected), "Native rootfs overlay paths differ from policy"
    )
    result = {}
    total = 0
    for path, record in data.items():
        require(
            isinstance(record, dict)
            and set(record) == {"content_base64", "sha256", "mode"},
            "Invalid overlay record",
        )
        encoded = record["content_base64"]
        require(
            isinstance(encoded, str) and len(encoded) <= 4 * ((MAX_FILE + 2) // 3),
            "Overlay file exceeds limit",
        )
        try:
            content = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError) as error:
            raise ValueError("Invalid overlay base64") from error
        require(
            base64.b64encode(content).decode() == encoded and len(content) <= MAX_FILE,
            "Noncanonical or oversized overlay content",
        )
        require(
            type(record["mode"]) is int and record["mode"] == expected[path],
            "Native overlay mode differs",
        )
        require(
            hashlib.sha256(content).hexdigest() == record["sha256"],
            "Native overlay digest differs",
        )
        total += len(content)
        require(total <= 1024**2, "Native rootfs overlay exceeds limit")
        result[path] = (content, record["mode"])
    return result


def promoted_overlay(catalog):
    result = decode_overlay(
        catalog.data["rootfs_overlay"], catalog.data["package_manager"]
    )
    # The source image has the pre-export seed. A personalized image carries
    # the complete approved target identity, including this catalog's digest.
    result["etc/asu-cohort.json"] = (canonical(catalog.identity) + b"\n", 0o644)
    return result


def _exec(container, command, cap):
    status, streams = container.exec_run(command, demux=True, user="1000:1000")
    stdout, stderr = streams
    stdout, stderr = stdout or b"", stderr or b""
    require(
        status == 0 and len(stdout) <= cap and len(stderr) <= 64 * 1024,
        "Actual rootfs inspection failed",
    )
    return stdout


def verify_apk_pins(catalog, manifest, read_file):
    """The attested IB hook generates these per-image, never from native FILES."""
    protected = read_file("etc/apk/ax6000-protected.list", 0o644, 1024**2)
    world = read_file("etc/apk/world", 0o644, 1024**2)
    require(
        protected.endswith(b"\n") and world.endswith(b"\n"),
        "APK root pin policy is truncated",
    )
    identities = catalog.data["package_identities"]
    actual = {
        identities[name]["name"]: (name, version) for name, version in manifest.items()
    }
    pins = {}
    for line in protected.decode("ascii").splitlines():
        name, separator, version = line.partition("=")
        require(
            separator and name not in pins and name in actual,
            "Invalid actual APK protected pin",
        )
        canonical_name, expected = actual[name]
        require(
            version == expected and not identities[canonical_name]["tag"],
            "APK protected package lost native version",
        )
        pins[name] = version
    roots = set(catalog.data["apk_protected_roots"]) | {
        "kernel",
        "libc",
        "base-files",
        "busybox",
        "apk-mbedtls",
        "apk-openssl",
    }
    roots.update(name for name in manifest if name.startswith("kmod-"))
    required = {identities[name]["name"] for name in roots & manifest.keys()}
    require(required <= pins.keys(), "APK image lost a mandatory native pin")
    rows = {}
    for line in world.decode("ascii").splitlines():
        match = re.fullmatch(
            r"([A-Za-z0-9][A-Za-z0-9+_.-]*)(?:@([A-Za-z0-9][A-Za-z0-9+_.-]*))?([<>=~].*)?",
            line,
        )
        require(
            match and match[1] not in rows,
            "Malformed or duplicate APK world constraint",
        )
        rows[match[1]] = line
    for name, version in pins.items():
        require(
            rows.get(name) == name + "=" + version, "APK world lost an exact native pin"
        )


def verify_sysupgrade_overlay(
    container, catalog, directory, request_hash, manifest, profile
):
    """Inspect the exact root member of the generated sysupgrade tar, not FILES."""
    metadata = Path(directory) / "profiles.json"
    require(
        metadata.is_file()
        and not metadata.is_symlink()
        and metadata.stat().st_size <= 4 * 1024**2,
        "Missing bounded image metadata",
    )
    content = json.loads(metadata.read_bytes())
    require(
        profile in catalog.data["profiles"] and set(content["profiles"]) == {profile},
        "Generated overlay inspection layout differs",
    )
    images = [
        image
        for profile in content["profiles"].values()
        for image in profile["images"]
        if image.get("type") == "sysupgrade" and image.get("filesystem") == "squashfs"
    ]
    require(len(images) == 1, "Exactly one generated sysupgrade root required")
    name = images[0].get("name", "")
    require(
        isinstance(name, str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,249}", name),
        "Unsafe sysupgrade output filename",
    )
    require(re.fullmatch("[0-9a-f]{64}", request_hash), "Invalid build hash")
    image = "/builder/" + request_hash + "/" + name
    with (Path(directory) / name).open("rb") as stream:
        expected_image_sha = hashlib.file_digest(stream, "sha256").hexdigest()

    def verify_image_sha():
        found = _exec(container, ["sha256sum", image], 4096).decode().split()
        require(
            len(found) == 2 and found[0] == expected_image_sha,
            "Inspected image differs from copied image bytes",
        )

    verify_image_sha()
    root = "/builder/.asu-inspected-root.squashfs"
    if profile.endswith("-ubootmod"):
        payload = static_fit_root(Path(directory) / name)
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as tar:
            member = tarfile.TarInfo(".asu-inspected-root.squashfs")
            member.mode = 0o644
            member.size = len(payload)
            tar.addfile(member, io.BytesIO(payload))
        require(
            container.put_archive("/builder/", archive.getvalue()),
            "Could not inspect actual FIT root",
        )
    else:
        require(profile.endswith(("-stock", "-mtkuboot")), "Unknown sysupgrade layout")
        members = (
            _exec(container, ["tar", "-tf", image], 64 * 1024)
            .decode("ascii")
            .splitlines()
        )
        roots = [
            member
            for member in members
            if re.fullmatch(r"sysupgrade-[A-Za-z0-9_.+-]+/root", member)
        ]
        require(
            len(roots) == 1 and members.count(roots[0]) == 1,
            "Exactly one sysupgrade SquashFS member required",
        )
        _exec(
            container,
            [
                "sh",
                "-c",
                'set -eu; set -C; tar -xOf "$1" "$2" > "$3"',
                "asu-overlay",
                image,
                roots[0],
                root,
            ],
            4096,
        )
    binary = "/builder/staging_dir/host/bin/unsquashfs4"
    base = [
        binary,
        "-processors",
        "1",
        "-data-queue",
        "8",
        "-frag-queue",
        "8",
        "-no-wildcards",
    ]
    evidence = {}

    def read_file(path, mode, limit=MAX_FILE):
        listing = _exec(container, [*base, "-lln", root, path], 64 * 1024)
        modes = re.findall(
            rb"^(\S+)\s+[^\n]*\s+squashfs-root/" + re.escape(path.encode()) + rb"$",
            listing,
            re.M,
        )
        expected_mode = {0o644: b"-rw-r--r--", 0o755: b"-rwxr-xr-x"}[mode]
        require(modes == [expected_mode], "Actual rootfs file mode differs: " + path)
        actual = _exec(container, [*base, "-cat", root, path], limit)
        evidence[path] = {"sha256": hashlib.sha256(actual).hexdigest(), "mode": mode}
        return actual

    for path, (expected, mode) in promoted_overlay(catalog).items():
        actual = read_file(path, mode)
        require(actual == expected, "Actual rootfs overlay bytes differ: " + path)
    if catalog.data["package_manager"] == "apk":
        verify_apk_pins(catalog, manifest, read_file)
    verify_image_sha()
    return evidence
