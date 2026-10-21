import logging
from collections import defaultdict
from datetime import datetime, UTC
from pathlib import Path
from typing import Union

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from asu import __version__
from asu.config import settings
from asu.ax6000_policy import get_catalog
from asu.routers import api, stats
from asu.store import LocalStore, get_store
from asu.util import (
    client_get,
    get_branch,
    is_post_kmod_split_build,
    parse_feeds_conf,
    parse_kernel_version,
    parse_packages_file,
    reload_targets,
    reload_versions,
)

logging.basicConfig(encoding="utf-8", level=settings.log_level)

base_path = Path(__file__).resolve().parent

app = FastAPI()


@app.middleware("http")
async def bounded_requests(request: Request, call_next):
    # Proxy and app both enforce bounds. Refuse unbounded/chunked POST input
    # before Pydantic buffers it. LuCI sends a finite JSON body.
    if get_catalog() and request.method == "POST":
        from fastapi.responses import JSONResponse

        length = request.headers.get("content-length", "")
        if not length.isdigit():
            return JSONResponse(
                {"detail": "Content-Length required", "status": 411}, status_code=411
            )
        if int(length) > 256 * 1024:
            return JSONResponse(
                {"detail": "Request body too large", "status": 413}, status_code=413
            )
    return await call_next(request)


app.include_router(api.router, prefix="/api/v1")
app.include_router(stats.router, prefix="/api/v1")

(settings.public_path / "store").mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory=base_path / "static"), name="static")

templates = Jinja2Templates(directory=base_path / "templates")

app.latest = []
app.versions = []
reload_versions(app)
logging.info(f"Found {len(app.versions)} versions")

app.targets = defaultdict(list)
app.profiles = defaultdict(lambda: defaultdict(dict))


@app.api_route("/store/{path:path}", methods=["GET", "HEAD"])
def store(path: str):
    store_backend = get_store()

    if isinstance(store_backend, LocalStore):
        store_root = (settings.public_path / "store").resolve()
        file_path = (store_root / path).resolve()
        if not file_path.is_file() or store_root not in file_path.parents:
            raise HTTPException(status_code=404, detail="Not found")

        return FileResponse(
            file_path,
            media_type="application/octet-stream",
            filename=file_path.name,
            headers={"X-Content-Type-Options": "nosniff"},
        )

    return RedirectResponse(store_backend.get_url(path), status_code=302)


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="overview.html",
        context=dict(
            versions=app.versions,
            branches=reversed(settings.branches),
            defaults=settings.allow_defaults,
            version=__version__,
            server_stats=settings.server_stats,
            max_custom_rootfs_size_mb=settings.max_custom_rootfs_size_mb,
            max_defaults_length=settings.max_defaults_length,
        ),
    )


@app.get("/stats", response_class=HTMLResponse)
def stats_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="stats.html",
        context=dict(
            branches=reversed(settings.branches),
        ),
    )


@app.get("/json/v1/{path:path}/index.json")
def json_v1_target_index(path: str) -> dict[str, Union[str, dict[str, str]]]:
    catalog = get_catalog()
    if catalog:
        if path != f"releases/{catalog.version}/targets/mediatek/filogic":
            raise HTTPException(status_code=404, detail="Unsupported catalog path")
        return {
            "architecture": catalog.data["firmware"]["architecture"],
            "packages": catalog.data["packages"],
        }
    base_path: str = f"{settings.upstream_url}/{path}"
    base_packages: dict[str, str] = parse_packages_file(f"{base_path}/packages")
    if is_post_kmod_split_build(path):
        kmods_directory: str = parse_kernel_version(f"{base_path}/profiles.json")
        if kmods_directory:
            kmod_packages: dict[str, str] = parse_packages_file(
                f"{base_path}/kmods/{kmods_directory}"
            )
            base_packages["packages"].update(kmod_packages.get("packages", {}))
    return base_packages


@app.get("/json/v1/{path:path}/{arch:path}-index.json")
def json_v1_arch_index(path: str, arch: str):
    catalog = get_catalog()
    if catalog:
        if (
            path != f"releases/{catalog.version}/packages"
            or arch != catalog.data["firmware"]["architecture"]
        ):
            raise HTTPException(status_code=404, detail="Unsupported catalog path")
        return {"architecture": arch, "packages": catalog.data["packages"]}
    feed_url: str = f"{settings.upstream_url}/{path}/{arch}"
    feeds: list[str] = parse_feeds_conf(feed_url)
    packages: dict[str, str] = {}
    for feed in feeds:
        packages.update(parse_packages_file(f"{feed_url}/{feed}").get("packages", {}))
    return packages


@app.get("/json/v1/{path:path}/targets/{target:path}/{profile:path}.json")
def json_v1_profile(path: str, target: str, profile: str):
    catalog = get_catalog()
    if catalog:
        if (
            path != f"releases/{catalog.version}"
            or target != "mediatek/filogic"
            or profile not in catalog.data["profiles"]
        ):
            raise HTTPException(status_code=404, detail="Unsupported catalog profile")
        data = catalog.data
        return {
            **data["firmware"],
            **data["profiles"][profile],
            "id": profile,
            "images": [],
            "ax6000": catalog.identity,
            "arch_packages": data["firmware"]["architecture"],
        }
    metadata: dict = client_get(
        f"{settings.upstream_url}/{path}/targets/{target}/profiles.json"
    ).json()
    profiles: dict = metadata.pop("profiles", {})
    if profile not in profiles:
        raise HTTPException(status_code=404, detail=f"Profile not found: {profile}")

    return {
        **metadata,
        **profiles[profile],
        "id": profile,
        "build_at": datetime.fromtimestamp(
            int(metadata.get("source_date_epoch", 0)), UTC
        ).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    }


def generate_latest():
    reload_versions(app)  # Do a reload in case .versions.json has updated.
    return app.latest


@app.get("/json/v1/latest.json")
def json_v1_latest():
    latest = generate_latest()
    return {"latest": latest}


def generate_branches():
    # Caller is responsible for calling reload_versions() beforehand.
    branches = dict(**settings.branches)

    for branch in branches:
        branches[branch]["versions"] = []
        branches[branch]["name"] = branch

    for version in app.versions:
        branch_name = get_branch(version)["name"]
        branches[branch_name]["versions"].append(version)

    for branch in branches:
        version = branches[branch]["versions"][0]
        if not app.targets[version]:
            reload_targets(app, version)

        branches[branch]["targets"] = app.targets[version]

    return branches


@app.get("/json/v1/branches.json")
def json_v1_branches():
    reload_versions(app)
    return list(generate_branches().values())


@app.get("/json/v1/overview.json")
def json_v1_overview():
    reload_versions(app)  # Single reload shared by both helpers.
    overview = {
        "latest": app.latest,
        "branches": generate_branches(),
        "upstream_url": settings.upstream_url,
        "server": {
            "version": __version__,
            "contact": "mail@aparcar.org",
            "allow_defaults": settings.allow_defaults,
            "repository_allow_list": settings.repository_allow_list,
            "max_custom_rootfs_size_mb": settings.max_custom_rootfs_size_mb,
            "max_defaults_length": settings.max_defaults_length,
        },
    }

    if get_catalog():
        overview["ax6000"] = get_catalog().identity
    return overview


@app.get("//{path:path}")
def api_double_slash(path: str):
    logging.info(f"Redirecting double slash to single slash: {path}")
    return RedirectResponse(f"/{path}", status_code=301)


# very legacy
@app.get("/overview")
def api_overview():
    return RedirectResponse("/json/v1/overview.json", status_code=301)
