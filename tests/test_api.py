"""AX6000 fork API contracts.

The upstream unrestricted ImageBuilder integration cases used moving Podman
images, arbitrary target repositories and client shell defaults. They are not
supported by this deployment. Real promoted-cohort submit/poll/identity cases
are in tests/ax6000/test_http_contract.py; actual native IB smoke is separate.
"""

import pytest
from asu.ax6000_policy import PolicyError
from asu.build_request import BuildRequest


def test_request_model_defaults():
    request = BuildRequest(
        version="24.10-SNAPSHOT",
        target="mediatek/filogic",
        profile="xiaomi_redmi-router-ax6000-stock",
    )
    assert request.packages == []
    assert request.packages_versions == {}
    assert request.installed_packages == []
    assert request.ax6000 is None
    assert request.defaults is None
    assert request.rootfs_size_mb is None


def test_no_catalog_cannot_queue_or_execute(client, monkeypatch):
    import asu.routers.api as api

    def no_engine(*args, **kwargs):
        raise AssertionError("Unconfigured requests must never access an engine/queue")

    monkeypatch.setattr(api, "get_queue", no_engine)
    response = client.post(
        "/api/v1/build",
        json={
            "version": "24.10-SNAPSHOT",
            "target": "mediatek/filogic",
            "profile": "xiaomi_redmi-router-ax6000-stock",
        },
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "No operator-promoted AX6000 catalog configured"


def test_unconfigured_worker_fails_before_lock_or_engine():
    from asu.build import build

    request = BuildRequest(
        version="24.10-SNAPSHOT",
        target="mediatek/filogic",
        profile="xiaomi_redmi-router-ax6000-stock",
    )
    with pytest.raises(PolicyError, match="operator-promoted"):
        build(request)


def test_api_missing_required_identity_fields(client):
    for field in ["target", "profile", "version"]:
        request = {
            "target": "mediatek/filogic",
            "profile": "xiaomi_redmi-router-ax6000-stock",
            "version": "24.10-SNAPSHOT",
        }
        request.pop(field)
        assert client.post("/api/v1/build", json=request).status_code == 422


def test_api_latest_overview_compatibility_redirects(client):
    for endpoint in ["latest", "overview"]:
        assert (
            client.get("/api/v1/" + endpoint, follow_redirects=False).status_code == 301
        )
