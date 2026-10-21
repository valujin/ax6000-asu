import datetime
import json
import logging
import re
import shutil
import tarfile
from io import BytesIO
from os import getenv
from pathlib import Path
from typing import Union
from time import perf_counter

from rq import get_current_job
from docker import errors
from rq.utils import parse_timeout

from asu.build_request import BuildRequest
from asu.config import settings
from asu.ax6000_policy import (
    get_catalog,
    validate_request,
    require,
    validate_manifest,
    image_package_specs,
    normalize_emitted_manifest,
)
from asu.repositories import (
    merge_repositories,
    validate_repos,
)
from asu.store import LocalStore, get_store
from asu.util import (
    add_timestamp,
    add_build_event,
    check_manifest,
    check_package_errors,
    diff_packages,
    error_log,
    fingerprint_pubkey_usign,
    get_branch,
    get_packages_hash,
    get_engine,
    get_request_hash,
    parse_manifest,
    report_error,
    run_cmd,
)

log = logging.getLogger("rq.worker")


def _cleanup_container(container):
    """Kill and remove a container with its volumes."""
    try:
        container.kill()
    except Exception:
        pass
    try:
        container.remove(v=True, force=True)
    except Exception as e:
        log.warning(f"Failed to remove container {container.id[:12]}: {e}")


def _make_tar(files: dict[str, str | bytes], modes=None) -> bytes:
    """Create an in-memory tar archive from a dict of {path: content}.

    Args:
        files: mapping of archive-relative paths to file contents
               (str will be encoded to utf-8)

    Returns:
        bytes of a tar archive
    """
    buf = BytesIO()
    with tarfile.TarFile(fileobj=buf, mode="w") as tar:
        for name, content in files.items():
            data = content.encode("utf-8") if isinstance(content, str) else content
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mode = (modes or {}).get(name, 0o644)
            tar.addfile(info, BytesIO(data))
    return buf.getvalue()


def _detect_apk_mode(container) -> bool:
    """Detect whether the ImageBuilder uses apk or opkg.

    Checks for the presence of /builder/repositories (apk) vs
    /builder/repositories.conf (opkg) inside the running container.
    """
    rc, _, _ = run_cmd(container, ["test", "-f", "/builder/repositories"])
    return rc == 0


def inject_files(container, build_request, job=None, apk_mode: bool | None = None):
    """Copy keys, repositories, and defaults into a running container.

    Uses put_archive to inject files directly — no bind mounts needed,
    so there are no host-path dependencies.

    Args:
        apk_mode: Pre-detected package manager mode (avoids redundant detection).
    """
    if build_request.repository_keys:
        files = {}
        for i, key in enumerate(build_request.repository_keys):
            if key.strip().startswith("-----BEGIN"):
                files[f"keys/custom-{i}.pem"] = key
            else:
                fingerprint = fingerprint_pubkey_usign(key)
                files[f"keys/{fingerprint}"] = (
                    f"untrusted comment: {fingerprint}\n{key}"
                )
        if files:
            container.put_archive("/builder/", _make_tar(files))

    if build_request.repositories:
        allowed = validate_repos(build_request.repositories)
        if apk_mode is None:
            apk_mode = _detect_apk_mode(container)
        repo_file = "repositories" if apk_mode else "repositories.conf"

        base = ""
        if build_request.repositories_mode == "append":
            _, base, _ = run_cmd(container, ["cat", repo_file])

        merged = merge_repositories(base, allowed, apk_mode)
        container.put_archive("/builder/", _make_tar({repo_file: merged}))

    if build_request.defaults:
        container.put_archive(
            "/builder/",
            _make_tar(
                {"asu-files/etc/uci-defaults/99-asu-defaults": build_request.defaults}
            ),
        )


def _build(build_request: BuildRequest, job=None, workspace=None, engine=None):
    """Build image request and setup ImageBuilders automatically

    The `request` dict contains properties of the requested image.

    Args:
        request (dict): Contains all properties of requested image
    """

    build_start: float = perf_counter()

    catalog = get_catalog()
    require(catalog is not None, "Build requires an operator-promoted AX6000 catalog")
    require(
        not getenv("BUILD_KEY"),
        "Worker image-certificate signing is not configured; BUILD_KEY is unsupported",
    )
    normalized = validate_request(catalog, build_request.model_dump())
    build_request = BuildRequest(**normalized)
    request_hash = get_request_hash(build_request)

    bin_dir: Path = Path(workspace) / request_hash
    bin_dir.mkdir(parents=True, exist_ok=True)
    log.debug(f"Bin dir: {bin_dir}")

    job = job or get_current_job()
    job.meta["detail"] = "init"
    job.meta["imagebuilder_status"] = "init"
    job.meta["request"] = build_request
    job.save_meta()

    log.debug(f"Building {build_request}")

    require(engine is not None, "Verified rootless engine required")

    log.debug(f"Build engine version: {engine.version()}")

    image = catalog.data["imagebuilder"]["image"]
    environment: dict[str, str] = {}
    job.meta["imagebuilder_status"] = "container_setup"
    job.save_meta()

    log.info(f"Verifying local ImageBuilder {image}...")
    try:
        engine.images.pull(image)
    except errors.ImageNotFound:
        report_error(
            job,
            f"Image not found: {image}. If this version was just released, please try again in a few hours as it may take some time to become fully available.",
        )
    log.info(f"Verifying local ImageBuilder {image}... done")

    mounts: list[dict[str, Union[str, bool]]] = [
        {"type": "tmpfs", "target": f"/builder/{request_hash}"},
    ]

    container = engine.containers.create(
        image,
        command=["sleep", str(parse_timeout(settings.job_timeout))],
        mounts=mounts,
        cap_drop=["all"],
        no_new_privileges=True,
        privileged=False,
        network_mode="bridge",
        networks={"asu-build": {}},
        environment=environment,
        image_volume_mode="ignore",
    )
    try:
        container.start()
        from asu.docker_engine import verify_runtime_limits, wait_for_global_lock

        wait_for_global_lock(container)

        job.meta["runtime_limits"] = verify_runtime_limits(container)
        job.save_meta()

        # No moving setup.sh, arbitrary repositories, keys, defaults or proxy rewriting.
        manager = catalog.data["package_manager"]
        apk_mode = _detect_apk_mode(container)
        require(
            apk_mode == (manager == "apk"),
            "ImageBuilder package manager differs from catalog",
        )
        keys = catalog.data["repository_keys"]
        repo_file = "repositories" if apk_mode else "repositories.conf"
        repo_content = catalog.data["repositories_conf"]
        if not apk_mode:
            repo_content += "\nsrc imagebuilder file:packages\n"
        files = {
            repo_file: repo_content,
        }
        from asu.overlay_policy import promoted_overlay, verify_sysupgrade_overlay

        overlay = promoted_overlay(catalog)
        files.update({"asu-files/" + path: value[0] for path, value in overlay.items()})
        modes = {"asu-files/" + path: value[1] for path, value in overlay.items()}
        for index, key in enumerate(keys):
            if apk_mode:
                require(
                    key.strip().startswith("-----BEGIN PUBLIC KEY-----"),
                    "APK requires PEM verification keys",
                )
                files["keys/approved-" + str(index) + ".pem"] = key
            else:
                fingerprint = fingerprint_pubkey_usign(key)
                files["keys/" + fingerprint] = key
        container.put_archive("/builder/", _make_tar(files, modes))

        returncode, job.meta["stdout"], job.meta["stderr"] = run_cmd(
            container, ["make", "info"]
        )

        job.meta["imagebuilder_status"] = "validate_revision"
        job.save_meta()

        version_code = re.search('Current Revision: "(r.+)"', job.meta["stdout"]).group(
            1
        )

        require(
            version_code == catalog.data["firmware"]["version_code"],
            "ImageBuilder revision differs from catalog",
        )
        if requested := build_request.version_code:
            if version_code != requested:
                report_error(
                    job,
                    f"Received incorrect version {version_code} (requested {requested})",
                )

        default_packages = set(
            re.search(r"Default Packages: (.*)\n", job.meta["stdout"]).group(1).split()
        )
        log.debug(f"Default packages: {default_packages}")

        profile_packages = set(
            re.search(
                r"{}:\n    .+\n    Packages: (.*?)\n".format(build_request.profile),
                job.meta["stdout"],
                re.MULTILINE,
            )
            .group(1)
            .split()
        )

        # Catalog policy deliberately keeps OPKG and the vendor package stack.

        extra_packages = (
            set(build_request.packages) - default_packages - profile_packages
        )
        branch = get_branch(build_request.version)["name"]
        for pkg in extra_packages:
            if not pkg.startswith("-"):
                add_timestamp(
                    f"stats:packages:{branch}:{pkg}",
                    {"stats": "packages", "branch": branch, "package": pkg},
                )

        build_cmd_packages = build_request.packages

        if build_request.diff_packages:
            build_cmd_packages: list[str] = diff_packages(
                build_request.packages, default_packages | profile_packages
            )
            log.debug(f"Diffed packages: {build_cmd_packages}")

        build_cmd_packages = image_package_specs(catalog, build_cmd_packages)
        job.meta["imagebuilder_status"] = "validate_manifest"
        job.save_meta()

        returncode, job.meta["stdout"], job.meta["stderr"] = run_cmd(
            container,
            [
                "make",
                "manifest",
                f"PROFILE={build_request.profile}",
                f"PACKAGES={' '.join(build_cmd_packages)}",
            ],
        )

        job.save_meta()

        if returncode:
            report_error(job, check_package_errors(job.meta["stderr"]))

        # Both managers emit actual indexed names. Never infer an ABI suffix or
        # accept an ABI-free name unless that is the approved actual identity.
        manifest: dict[str, str] = normalize_emitted_manifest(
            catalog, parse_manifest(job.meta["stdout"])
        )
        log.debug(f"Manifest: {manifest}")

        # Check if all requested packages are in the manifest
        if err := check_manifest(manifest, build_request.packages_versions):
            report_error(job, err)

        validate_manifest(catalog, build_request.model_dump(), manifest)
        packages_hash: str = get_packages_hash(manifest.keys())
        log.debug(f"Packages Hash: {packages_hash}")

        job.meta["build_cmd"] = [
            "make",
            "image",
            f"PROFILE={build_request.profile}",
            f"PACKAGES={' '.join(build_cmd_packages)}",
            f"EXTRA_IMAGE_NAME={packages_hash[:12]}",
            f"BIN_DIR=/builder/{request_hash}",
            "FILES=/builder/asu-files",
        ]

        if build_request.defaults:
            job.meta["build_cmd"].append("FILES=/builder/asu-files")

        # Check if custom rootfs size is requested
        if build_request.rootfs_size_mb:
            log.debug("Found custom rootfs size %d", build_request.rootfs_size_mb)
            job.meta["build_cmd"].append(
                f"ROOTFS_PARTSIZE={build_request.rootfs_size_mb}"
            )

        if build_request.filesystem:
            log.debug("Restricting filesystem to %s", build_request.filesystem)
            job.meta["build_cmd"].append(
                f"ROOTFS_FILESYSTEM={build_request.filesystem}"
            )

        log.debug("Build command: %s", job.meta["build_cmd"])

        job.meta["imagebuilder_status"] = "building_image"
        job.save_meta()

        returncode, job.meta["stdout"], job.meta["stderr"] = run_cmd(
            container,
            job.meta["build_cmd"],
            copy=["/builder/" + request_hash, bin_dir.parent],
        )
        if returncode == 0:
            job.meta["rootfs_overlay"] = verify_sysupgrade_overlay(
                container,
                catalog,
                bin_dir,
                request_hash,
                manifest,
                build_request.profile,
            )
            job.save_meta()
    finally:
        _cleanup_container(container)

    job.save_meta()

    if any(err in job.meta["stderr"] for err in ["is too big", "out of space?"]):
        report_error(job, "Selected packages exceed device storage")

    if returncode:
        report_error(job, "Error while building firmware. See stdout/stderr")

    json_file = bin_dir / "profiles.json"

    if not json_file.is_file():
        report_error(job, "No JSON file found")

    json_content = json.loads(json_file.read_text())

    # Check if profile is in JSON file
    if build_request.profile not in json_content["profiles"]:
        report_error(job, "Profile not found in JSON file")

    require(
        json_content.get("target") == "mediatek/filogic"
        and json_content.get("version_code")
        == catalog.data["firmware"]["version_code"],
        "Built image identity differs",
    )
    result_profile = json_content["profiles"][build_request.profile]
    require(
        result_profile.get("supported_devices")
        == catalog.data["profiles"][build_request.profile]["supported_devices"],
        "Built layout differs",
    )
    images_metadata = result_profile.get("images", [])
    sysupgrade = [
        x
        for x in images_metadata
        if x.get("type") == "sysupgrade" and x.get("filesystem") == "squashfs"
    ]
    require(len(sysupgrade) == 1, "Exactly one sysupgrade image required")
    for record in images_metadata:
        name = record.get("name", "")
        require(
            isinstance(name, str)
            and Path(name).name == name
            and name not in ("", ".", ".."),
            "Unsafe output filename",
        )
        output = bin_dir / name
        require(output.is_file() and not output.is_symlink(), "Output image missing")
        if record.get("type") == "sysupgrade":
            import hashlib

            require(
                output.stat().st_size
                <= catalog.data["profiles"][build_request.profile]["max_image_size"],
                "Image exceeds layout partition bound",
            )
            with output.open("rb") as stream:
                require(
                    hashlib.file_digest(stream, "sha256").hexdigest()
                    == record.get("sha256"),
                    "Output image checksum differs",
                )
    from asu.manifest_policy import verify_emitted_manifest

    manifest = verify_emitted_manifest(
        catalog, build_request.model_dump(), bin_dir, manifest
    )

    import hashlib

    for record in images_metadata:
        output = bin_dir / record["name"]
        with output.open("rb") as stream:
            record["sha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
        record["size"] = output.stat().st_size
        if record.get("type") == "sysupgrade":
            require(
                record["size"]
                <= catalog.data["profiles"][build_request.profile]["max_image_size"],
                "Signed image exceeds partition bound",
            )
    # Persist checksums for the actual (optionally signed) bytes, before the
    # directory becomes downloadable. The API response is flattened afterward.
    json_content["ax6000"] = catalog.identity
    json_file.write_text(json.dumps(json_content, sort_keys=True) + "\n")
    checksums = []
    for output in sorted(bin_dir.iterdir()):
        if output.is_file() and output.name not in {"sha256sums", "SHA256SUMS"}:
            with output.open("rb") as stream:
                checksums.append(
                    hashlib.file_digest(stream, "sha256").hexdigest()
                    + "  "
                    + output.name
                    + "\n"
                )
    for name in ("sha256sums", "SHA256SUMS"):
        (bin_dir / name).write_text("".join(checksums))
    store = get_store()
    store.upload_dir(bin_dir, request_hash)

    if not isinstance(store, LocalStore):
        shutil.rmtree(bin_dir, ignore_errors=True)

    json_content.update({"manifest": manifest, "ax6000": catalog.identity})
    json_content.update(json_content["profiles"][build_request.profile])
    json_content["id"] = build_request.profile
    json_content["bin_dir"] = request_hash
    json_content["build_cmd_packages"] = build_cmd_packages
    json_content.pop("profiles")
    json_content["build_at"] = datetime.datetime.fromtimestamp(
        int(json_content.get("source_date_epoch", 0))
    ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    json_content["detail"] = "done"

    log.debug("JSON content %s", json_content)

    add_timestamp(
        f"stats:builds:{build_request.version}:{build_request.target}:{build_request.profile}",
        {
            "stats": "builds",
            "version": build_request.version,
            "target": build_request.target,
            "profile": build_request.profile,
        },
    )

    # Calculate build duration and log it
    build_duration: float = round(perf_counter() - build_start)
    add_timestamp(
        f"stats:time:{build_request.version}:{build_request.target}:{build_request.profile}",
        {
            "stats": "time",
            "version": build_request.version,
            "target": build_request.target,
            "profile": build_request.profile,
        },
        build_duration,
    )

    job.meta["imagebuilder_status"] = "done"
    job.save_meta()

    return json_content


def build(build_request: BuildRequest, job=None):
    require(
        get_catalog() is not None,
        "Build requires an operator-promoted AX6000 catalog",
    )
    try:
        import fcntl

        lock_path = getenv("ASU_GLOBAL_BUILD_LOCK", "/build-lock/.build.lock")
        with open(lock_path, "r") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            from asu.cache_policy import prune_cache, discard_invalid_build_cache

            engine = get_engine()
            engine.reap_orphans()
            prune_cache(settings.public_path)
            catalog = get_catalog()
            normalized = BuildRequest(
                **validate_request(catalog, build_request.model_dump())
            )
            discard_invalid_build_cache(
                settings.public_path, get_request_hash(normalized), catalog.identity
            )
        # The parent releases its short setup lock before starting PID1's lock
        # holder. No image/package work runs until the unique ready token appears.
        import tempfile

        settings.public_path.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix=".asu-", dir=settings.public_path
        ) as workspace:
            result = _build(build_request, job, workspace=workspace, engine=engine)

    except Exception as exc:
        # Log all build errors, including internal server errors.
        try:
            add_build_event("failures")
            error_log.log_build_error(build_request, str(exc))
        except Exception:
            log.warning("Could not persist build failure; original error retained")
        raise
    else:
        add_build_event("successes")
        return result
