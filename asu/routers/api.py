import logging
from typing import Union

from fastapi import APIRouter, Header, Request
from fastapi.responses import RedirectResponse, Response
from rq.job import Job

from asu.build_request import BuildRequest
from asu.config import settings
from asu.cache_policy import published_cache_valid
from asu.ax6000_policy import (
    get_catalog,
    validate_request as validate_policy,
    PolicyError,
)
from asu.util import (
    add_timestamp,
    add_build_event,
    client_get,
    get_branch,
    get_queue,
    get_request_hash,
)

router = APIRouter()


def get_distros() -> list:
    """Return available distributions

    Returns:
        list: Available distributions
    """
    return ["openwrt"]


@router.get("/revision/{version}/{target}/{subtarget}")
def api_v1_revision(
    version: str, target: str, subtarget: str, response: Response, request: Request
):
    catalog = get_catalog()
    if catalog:
        if version != catalog.version or target + "/" + subtarget != "mediatek/filogic":
            response.status_code = 400
            return {"detail": "Unsupported cohort target/version", "status": 400}
        return {
            "revision": catalog.data["firmware"]["version_code"],
            "ax6000": catalog.identity,
        }
    branch_data = get_branch(version)
    if "path" not in branch_data:
        response.status_code = 400
        return {
            "detail": f"Unsupported version: {version}",
            "status": 400,
        }
    version_path = branch_data["path"].format(version=version)
    req = client_get(
        settings.upstream_url
        + f"/{version_path}/targets/{target}/{subtarget}/profiles.json"
    )

    if req.status_code != 200:
        response.status_code = req.status_code
        return {
            "detail": f"Failed to fetch revision for {version}/{target}/{subtarget}",
            "status": req.status_code,
        }

    return {"revision": req.json()["version_code"]}


@router.get("/latest")
def api_latest():
    return RedirectResponse("/json/v1/latest.json", status_code=301)


@router.get("/overview")
def api_v1_overview():
    return RedirectResponse("/json/v1/overview.json", status_code=301)


def validation_failure(detail: str) -> tuple[dict[str, Union[str, int]], int]:
    logging.info(f"Validation failure {detail = }")
    return {"detail": detail, "status": 400}, 400


def validate_request(
    app,
    build_request: BuildRequest,
) -> tuple[dict[str, Union[str, int]], int]:
    """Validate an image request and return found errors with status code

    Instead of building every request it is first validated. This checks for
    existence of requested profile, distro, version and package.

    Args:
        req (dict): The image request

    Returns:
        (dict, int): Status message and code, empty if no error appears

    """

    catalog = get_catalog()
    if not catalog:
        return validation_failure("No operator-promoted AX6000 catalog configured")
    if catalog:
        try:
            normalized = validate_policy(catalog, build_request.model_dump())
            for key, value in normalized.items():
                setattr(build_request, key, value)
            return ({}, None)
        except PolicyError as error:
            return validation_failure(str(error))


def return_job_v1(job: Job) -> tuple[dict, int, dict]:
    response: dict = job.get_meta()
    imagebuilder_status: str = "done"
    queue_position: int = 0

    if job.meta:
        response.update(job.meta)

    if job.is_failed:
        error_message: str = job.latest_result().exc_string
        if "stderr" in response:
            error_message = response["stderr"] + "\n" + error_message
        detail: str = response.get("detail", "failed")
        if detail == "init":  # Happens when container startup fails.
            detail = "failed"
        response.update(status=500, detail=detail, stderr=error_message)
        imagebuilder_status = "failed"

    elif job.is_queued:
        queue_position = job.get_position() or 0
        response.update(status=202, detail="queued", queue_position=queue_position)
        imagebuilder_status = "queued"

    elif job.is_started:
        response.update(status=202, detail="started")
        imagebuilder_status = response.get("imagebuilder_status", "init")

    elif job.is_finished:
        response.update(status=200, **job.return_value())
        imagebuilder_status = "done"

    headers = {
        "X-Imagebuilder-Status": imagebuilder_status,
        "X-Queue-Position": str(queue_position),
    }

    response.update(enqueued_at=job.enqueued_at, request_hash=job.id)

    logging.debug(response)
    return response, response["status"], headers


@router.head("/build/{request_hash}")
@router.get("/build/{request_hash}")
def api_v1_build_get(request: Request, request_hash: str, response: Response) -> dict:
    queue = get_queue()
    # A stale Job.delete can otherwise delete a replacement queued under the
    # same hash. Fetch, validate and invalidate share POST's admission lock.
    with queue.connection.lock("asu:global-admission", timeout=120, blocking_timeout=2):
        job = fetch_valid_job(queue, request_hash)
    if not job:
        response.status_code = 404
        return {
            "status": 404,
            "title": "Not Found",
            "detail": "could not find provided request hash",
        }

    content, status, headers = return_job_v1(job)
    response.headers.update(headers)
    response.status_code = status

    return content


def fetch_valid_job(queue, request_hash):
    """Caller must hold global admission lock; never act on a stale Job."""
    job: Job = queue.fetch_job(request_hash)
    catalog = get_catalog()
    if (
        job
        and catalog
        and (
            job.kwargs.get("cohort") != catalog.data["cohort"]
            or job.kwargs.get("catalog_sha256") != catalog.sha256
        )
    ):
        job = None
    if (
        job
        and job.is_finished
        and not published_cache_valid(settings.public_path, job.return_value())
    ):
        job.delete()
        job = None
    return job


@router.post("/build")
def api_v1_build_post(
    build_request: BuildRequest,
    response: Response,
    request: Request,
    user_agent: str = Header(None),
):
    # Sanitize the profile in case the client did not (bug in older LuCI app).
    build_request.profile = build_request.profile.replace(",", "_")

    add_build_event("requests")

    # Validate every request before cache lookup, including cache hits.
    catalog = get_catalog()
    content, status = validate_request(request.app, build_request)
    if content:
        response.status_code = status
        return content
    request_hash: str = get_request_hash(build_request)
    status: int = 200
    if build_request.defaults:
        result_ttl = settings.build_defaults_ttl
    elif build_request.packages_versions:
        result_ttl = settings.build_ttl
    else:
        result_ttl = settings.build_ttl_unversioned
    failure_ttl: str = settings.build_failure_ttl

    if build_request.client:
        client = build_request.client
    elif user_agent and user_agent.startswith("auc"):
        client = user_agent.replace(" (", "/").replace(")", "")
    else:
        client = "unknown/0"

    add_timestamp(
        f"stats:clients:{client}",
        {"stats": "clients", "client": client},
    )

    # Serialize reads, invalidation and admission across all API processes.
    # The separate filesystem flock serializes actual heavy execution.
    queue = get_queue()
    with queue.connection.lock("asu:global-admission", timeout=120, blocking_timeout=2):
        job = fetch_valid_job(queue, request_hash)
        if job is None:
            job_queue_length = len(queue)
            if job_queue_length >= settings.max_pending_jobs:
                response.status_code = 529
                return {
                    "status": 529,
                    "title": "Server overloaded",
                    "detail": "Global build queue is full",
                }
            add_build_event("cache-misses")
            job = queue.enqueue(
                "asu.jobs.run",
                kwargs={
                    "cohort": catalog.data["cohort"],
                    "catalog_sha256": catalog.sha256,
                    "request": build_request.model_dump(),
                },
                job_id=request_hash,
                result_ttl=result_ttl,
                failure_ttl=failure_ttl,
                job_timeout=settings.job_timeout,
            )

        elif job.is_finished:
            add_build_event("cache-hits")

    content, status, headers = return_job_v1(job)
    response.headers.update(headers)
    response.status_code = status

    return content


@router.get("/stats")
def api_v1_builder_stats():
    """Return status of builders

    Returns:
        queue_length: Number of jobs currently in build queue
    """
    return {
        "queue_length": len(get_queue()),
    }
