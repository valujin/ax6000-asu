from fakeredis import FakeStrictRedis

from asu.build_request import BuildRequest

build_config_1 = dict(
    version="1.2.3",
    target="testtarget/testsubtarget",
    profile="testprofile",
    packages=["test1"],
)

build_config_2 = dict(
    version="1.2.3",
    target="testtarget/testsubtarget",
    profile="testprofile",
    packages=["test1", "test2"],
)


class Stats:
    def __init__(self, redis_server: FakeStrictRedis):
        self.ts = redis_server.ts()

    def summary(self, type):
        key = f"stats:build:{type}"
        if self.ts.client.exists(key):
            return self.ts.range(key, "-", "+")
        return []

    def client(self, tag):
        clients = self.ts.mrange("-", "+", filters=["stats=clients"])
        if not clients:
            return []
        return clients[0][f"stats:clients:{tag}"]

    def builds(self, tag):
        builds = self.ts.mrange("-", "+", filters=["stats=builds"])
        if not builds:
            return []
        return builds[0][f"stats:builds:{tag}"]


def test_stats_record_events_without_image_execution(client, redis_server):
    from asu.util import add_build_event, add_timestamp

    stats = Stats(redis_server)
    assert stats.summary("requests") == []
    add_build_event("requests")
    add_build_event("cache-misses")
    add_build_event("successes")
    assert len(stats.summary("requests")) == 1
    assert len(stats.summary("cache-misses")) == 1
    assert len(stats.summary("successes")) == 1
    add_timestamp("stats:clients:test/1", {"stats": "clients", "client": "test/1"})
    assert len(stats.client("test/1")[1]) == 1


def test_stats_builds_per_day(client, redis_server: FakeStrictRedis):
    from asu.routers.stats import N_DAYS

    response = client.get("/api/v1/builds-per-day")
    assert response.status_code == 200

    data = response.json()
    assert "labels" in data
    assert len(data["labels"]) == N_DAYS
    assert "datasets" in data
    assert "data" in data["datasets"][0]
    assert len(data["datasets"][0]["data"]) == N_DAYS


def test_stats_builds_by_version(client, redis_server: FakeStrictRedis):
    from asu.util import add_timestamp

    add_timestamp(
        "stats:builds:1.2.3:testtarget/testsubtarget:testprofile",
        {
            "stats": "builds",
            "version": "1.2.3",
            "target": "testtarget/testsubtarget",
            "profile": "testprofile",
        },
    )

    response = client.get("/api/v1/builds-by-version")
    assert response.status_code == 200

    data = response.json()
    assert "labels" in data
    assert len(data["labels"]) == 26
    assert "datasets" in data
    assert len(data["datasets"]) == 1
    assert len(data["datasets"][0]["data"]) == 26

    response = client.get("/api/v1/builds-by-version?branch=1.2")
    assert response.status_code == 200

    data = response.json()
    assert len(data["labels"]) == 26
    assert len(data["datasets"][0]["data"]) == 26


def test_build_error_log(client, redis_server):
    """Test that build errors are logged to Redis."""
    from asu.util import ErrorLog

    error_log = ErrorLog()

    # Clear any existing errors
    redis_server.delete(ErrorLog.REDIS_KEY)

    # Initially should have no errors
    response = client.get("/api/v1/build-errors")
    assert response.status_code == 200
    assert "No build errors recorded" in response.text

    # Log an error
    build_request = BuildRequest(
        distro="openwrt",
        version="24.10-SNAPSHOT",
        version_code="",
        target="ath79/generic",
        profile="tplink_tl-wdr4300-v1",
        packages=["vim"],
    )
    error_log.log_build_error(build_request, "Test error message")

    entries = error_log.get_entries()
    assert len(entries) == 1
    assert "24.10-SNAPSHOT:ath79/generic:tplink_tl-wdr4300-v1" in entries[0]
    assert "Test error message" in entries[0]

    # Log another — most recent should be first
    error_log.log_build_error(build_request, "Second error")
    entries = error_log.get_entries()
    assert len(entries) == 2
    assert "Second error" in entries[0]

    # Test summary format
    summary = error_log.get_summary()
    assert "Build Errors: 2 entries" in summary
    assert "Time range:" in summary

    # Test sanitization of job hashes
    error_log.log_build_error(
        build_request,
        "Internal Server Error (no container with ID "
        "eee08b3b7b072f2ba82559c6e61da9b84e00cdbc35a4d99392fec36c0bf64356"
        " found in database: no such container)",
    )
    entries = error_log.get_entries()
    assert " ID [job-id] found " in entries[0]


def test_build_error_log_api(client):
    """Test the /api/v1/build-errors endpoint."""
    response = client.get("/api/v1/build-errors")
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/plain; charset=utf-8"

    response = client.get("/api/v1/build-errors?n=50")
    assert response.status_code == 200


def test_build_error_log_respects_n_entries(client, redis_server):
    """Test that get_entries respects n_entries limit."""
    from asu.util import ErrorLog

    error_log = ErrorLog()
    redis_server.delete(ErrorLog.REDIS_KEY)

    build_request = BuildRequest(
        version="1.2.3",
        target="testtarget/testsubtarget",
        profile="testprofile",
    )

    for i in range(10):
        error_log.log_build_error(build_request, f"Error {i}")

    entries = error_log.get_entries(n_entries=3)
    assert len(entries) == 3
    assert "Error 9" in entries[0]
