"""RQ entry point. Import no ASU configuration before fork/cohort selection."""

import json
import os
from pathlib import Path

COHORTS = {"66", "612-recommended", "612-latest"}


def run(cohort, catalog_sha256, request):
    """All arguments are plain JSON values, avoiding premature Pydantic imports.

    The RQ worker must use its normal fork-per-job model. It must never preload
    asu.config/main/build, and must not use SimpleWorker or threaded execution.
    """
    import sys

    if "asu.config" in sys.modules:
        raise RuntimeError("Worker preloaded ASU settings; fork isolation is required")
    if cohort not in COHORTS:
        raise ValueError("Unknown cohort")
    directory = Path(os.environ.get("ASU_COHORT_CONFIG_DIR", "/config/cohorts"))
    config_path = directory / (cohort + ".json")
    if (
        config_path.is_symlink()
        or not config_path.is_file()
        or config_path.stat().st_size > 32768
    ):
        raise ValueError("Missing bounded trusted cohort configuration")
    cfg = json.loads(config_path.read_bytes())
    if cfg.get("cohort") != cohort or cfg.get("catalog_sha256") != catalog_sha256:
        raise ValueError("Queued generation is no longer approved")
    from asu.ax6000_policy import Catalog, validate_request

    catalog = Catalog.load(cfg["catalog"], catalog_sha256, cohort)
    request = validate_request(catalog, request)
    # Only this fixed set can affect the child; no arbitrary environment mapping.
    os.environ.update(
        {
            "ASU_AX6000_COHORT": cohort,
            "ASU_AX6000_CATALOG": cfg["catalog"],
            "ASU_AX6000_CATALOG_SHA256": catalog_sha256,
            "PUBLIC_PATH": cfg["public_path"],
            "REDIS_URL": os.environ["REDIS_URL"],
        }
    )
    from asu.build_request import BuildRequest
    from asu.build import build

    return build(BuildRequest(**request))
