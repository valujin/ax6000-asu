"""Bound worker-produced cache files; no arbitrary paths or symlink traversal."""

import re
import shutil
import time
from pathlib import Path


def discard_invalid_build_cache(public_path, build_hash, identity):
    """Worker-only recovery, while holding the shared global build lock.

    APIs invalidate stale RQ results without filesystem writes. A later worker
    removes only the rejected request's corrupt directory before republishing.
    """
    import json

    if not re.fullmatch("[0-9a-f]{64}", build_hash):
        raise ValueError("Invalid build cache hash")
    base = Path(public_path) / "store"
    root = base / build_hash
    if base.is_symlink() or root.is_symlink():
        raise ValueError("Build cache directory may not be a symlink")
    if not root.exists():
        return False
    if not root.is_dir():
        raise ValueError("Build cache path must be a directory")
    valid = False
    try:
        metadata = root / "profiles.json"
        if metadata.is_symlink() or metadata.stat().st_size > 4 * 1024**2:
            raise ValueError("Invalid bounded cache metadata")
        content = json.loads(metadata.read_bytes())
        records = [
            record
            for profile in content["profiles"].values()
            for record in profile["images"]
        ]
        valid = content.get("ax6000") == identity and published_cache_valid(
            public_path, {"bin_dir": build_hash, "images": records}
        )
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        pass
    if valid:
        return False
    shutil.rmtree(root)
    return True


def prune_cache(public_path, *, max_bytes=20 * 1024**3, max_age=7 * 86400, now=None):
    now = time.time() if now is None else now
    public = Path(public_path)
    # A single worker runs this before admitting heavy execution. Old private
    # workspaces can remain after an RQ hard timeout; never expose or retain them.
    if public.exists():
        for orphan in public.glob(".asu-*"):
            if orphan.is_dir() and not orphan.is_symlink():
                shutil.rmtree(orphan)
    root = public / "store"
    if not root.exists():
        return []
    if root.is_symlink():
        raise ValueError("Cache root may not be a symlink")
    entries = []
    for directory in root.iterdir():
        if (
            not re.fullmatch("[0-9a-f]{64}", directory.name)
            or directory.is_symlink()
            or not directory.is_dir()
        ):
            continue
        size = 0
        for item in directory.rglob("*"):
            if item.is_symlink():
                raise ValueError("Symlink in build cache")
            if item.is_file():
                size += item.stat().st_size
        entries.append((directory.stat().st_mtime, size, directory))
    remaining = sum(x[1] for x in entries)
    removed = []
    for modified, size, directory in sorted(entries):
        if now - modified <= max_age and remaining <= max_bytes:
            continue
        shutil.rmtree(directory)
        remaining -= size
        removed.append(directory.name)
    return removed


def published_cache_valid(public_path, result):
    """RQ results never outlive downloadable validated image bytes."""
    import hashlib

    try:
        build_hash = result.get("bin_dir", "")
        if not re.fullmatch("[0-9a-f]{64}", build_hash):
            return False
        root = Path(public_path) / "store" / build_hash
        if root.is_symlink() or not root.is_dir():
            return False
        images = result.get("images", [])
        if not images:
            return False
        for record in images:
            name = record.get("name", "")
            if not name or Path(name).name != name:
                return False
            path = root / name
            if (
                path.is_symlink()
                or not path.is_file()
                or path.stat().st_size != record.get("size")
            ):
                return False
            with path.open("rb") as stream:
                if hashlib.file_digest(stream, "sha256").hexdigest() != record.get(
                    "sha256"
                ):
                    return False
        return True
    except (OSError, ValueError, TypeError, AttributeError):
        return False
