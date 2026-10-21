"""Validate the actual emitted image closure, independently of preflight output."""

from pathlib import Path
from asu.ax6000_policy import require, normalize_emitted_manifest, validate_manifest


def parse_manifest_text(content):
    separator = " - " if " - " in content else " "
    result = {}
    for line in content.splitlines():
        name, version = line.split(separator)
        if name in result:
            raise ValueError("Duplicate emitted manifest package")
        result[name] = version
    return result


def verify_emitted_manifest(catalog, request, directory, preflight):
    files = sorted(Path(directory).glob("*.manifest"))
    require(
        len(files) == 1 and files[0].is_file() and not files[0].is_symlink(),
        "Exactly one emitted image manifest required",
    )
    require(files[0].stat().st_size <= 4 * 1024**2, "Emitted manifest exceeds limit")
    actual = normalize_emitted_manifest(
        catalog, parse_manifest_text(files[0].read_text())
    )
    validate_manifest(catalog, request, actual)
    require(actual == preflight, "Final emitted package closure differs from preflight")
    return actual
