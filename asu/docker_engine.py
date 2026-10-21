"""Docker-only adapter; never defaults to the host's production daemon."""

import os
from pathlib import Path

MEMORY = 10 * 1024**3
BUILD_LABEL = "io.valujin.ax6000-asu.build"
HOST_BUILD_LOCK = "/home/valuxin/dev/owrt/ax6000-packages-build/work/.build.lock"


class EngineError(RuntimeError):
    pass


def assert_rootless(info, expected_id):
    options = info.get("SecurityOptions", [])
    if (
        not expected_id
        or info.get("ID") != expected_id
        or not any(
            x == "name=rootless" or x.startswith("name=rootless,") for x in options
        )
    ):
        raise EngineError("Build engine is not the approved rootless daemon")


def assert_build_limits(inspect):
    host = inspect.get("HostConfig", {})
    expected = {
        "CpuPeriod": 100000,
        "CpuQuota": 400000,
        "CpusetCpus": "0-3",
        "Memory": MEMORY,
        "MemorySwap": MEMORY,
        "PidsLimit": 2048,
        "Privileged": False,
        "NetworkMode": "asu-build",
    }
    if any(host.get(k) != v for k, v in expected.items()):
        raise EngineError("Build engine did not apply resource/isolation limits")
    if {x.upper() for x in host.get("CapDrop") or []} != {"ALL"} or host.get("CapAdd"):
        raise EngineError("Build container capabilities differ")
    if not any(
        x.split(":")[0].split("=")[0] == "no-new-privileges"
        for x in host.get("SecurityOpt") or []
    ):
        raise EngineError("Build container lacks no-new-privileges")
    if inspect.get("Config", {}).get("User") != "1000:1000":
        raise EngineError("Build container must run as buildbot")
    if host.get("PidMode") == "host" or host.get("IpcMode") == "host":
        raise EngineError("Host process namespaces are forbidden")


class Images:
    def __init__(self, client):
        self.client = client

    def pull(self, image):
        # Kept as an adapter method for the upstream build workflow: no network pull.
        obj = self.client.images.get(image)
        if image.startswith("sha256:"):
            if obj.id != image:
                raise EngineError("Loaded ImageBuilder ID differs")
        elif image not in obj.attrs.get("RepoDigests", []):
            raise EngineError("Loaded ImageBuilder repository digest differs")
        return obj


class Containers:
    def __init__(self, client):
        self.client = client

    def create(self, image, **kwargs):
        from docker.types import Mount, LogConfig

        import secrets

        lock_token = secrets.token_hex(16)
        mounts = [
            Mount(
                "/build-lock/.build.lock", HOST_BUILD_LOCK, type="bind", read_only=True
            )
        ]
        for m in kwargs.pop("mounts", []):
            if m["type"] == "tmpfs":
                mounts.append(
                    Mount(
                        m["target"],
                        None,
                        type="tmpfs",
                        tmpfs_size=512 * 1024**2,
                        tmpfs_mode=0o1777,
                    )
                )
            else:
                raise EngineError("Additional host bind mounts are forbidden")
        kwargs.pop("network_mode", None)
        kwargs.pop("networks", None)
        kwargs.pop("image_volume_mode", None)
        kwargs.pop("no_new_privileges", None)
        if kwargs.pop("privileged", False):
            raise EngineError("Privileged build forbidden")
        if kwargs.pop("user", "1000:1000") != "1000:1000":
            raise EngineError(
                "Root signing containers are forbidden; use external signer"
            )
        kwargs.pop("cap_drop", None)
        kwargs.pop("command", None)
        environment = kwargs.pop("environment", {})
        environment["ASU_LOCK_TOKEN"] = lock_token
        command = [
            "timeout",
            "--foreground",
            "--kill-after=10s",
            "1200",
            "flock",
            "-x",
            "/build-lock/.build.lock",
            "sh",
            "-c",
            'printf %s "$ASU_LOCK_TOKEN" > /builder/.asu-lock-held; exec sleep 86400',
        ]
        container = self.client.containers.create(
            image,
            **kwargs,
            labels={BUILD_LABEL: "true"},
            entrypoint=[],
            command=command,
            environment=environment,
            mounts=mounts,
            user="1000:1000",
            network="asu-build",
            cpu_period=100000,
            cpu_quota=400000,
            cpuset_cpus="0-3",
            mem_limit=MEMORY,
            memswap_limit=MEMORY,
            pids_limit=2048,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges"],
            privileged=False,
            init=False,
            log_config=LogConfig(
                type="local", config={"max-size": "2m", "max-file": "2"}
            ),
        )
        try:
            container.reload()
            assert_build_limits(container.attrs)
        except Exception:
            container.remove(v=True, force=True)
            raise
        lock_path = os.environ.get("ASU_GLOBAL_BUILD_LOCK", "/build-lock/.build.lock")
        lock_stat = os.stat(lock_path)
        container.asu_lock_identity = f"{lock_stat.st_dev}:{lock_stat.st_ino}"
        container.asu_lock_token = lock_token
        return container


class DockerEngine:
    def __init__(self):
        import docker

        url = os.environ.get("ASU_BUILD_ENGINE_URL", "")
        if not url.startswith("unix:///"):
            raise EngineError("Explicit rootless Unix engine socket required")
        path = url.removeprefix("unix://")
        if Path(path).resolve() in (
            Path("/var/run/docker.sock").resolve(),
            Path("/run/docker.sock").resolve(),
        ):
            raise EngineError("Production Docker socket is forbidden")
        self.client = docker.DockerClient(base_url=url, timeout=60)
        assert_rootless(self.client.info(), os.environ.get("ASU_BUILD_ENGINE_ID"))
        self.images = Images(self.client)
        self.containers = Containers(self.client)

    def reap_orphans(self):
        """Call only while holding the shared heavy-build flock."""
        assert_rootless(self.client.info(), os.environ.get("ASU_BUILD_ENGINE_ID"))
        for container in self.client.containers.list(
            all=True, filters={"label": BUILD_LABEL + "=true"}
        ):
            container.reload()
            if (
                container.attrs.get("Config", {}).get("Labels", {}).get(BUILD_LABEL)
                != "true"
            ):
                raise EngineError("Refusing to remove foreign container")
            container.remove(v=True, force=True)

    def version(self):
        assert_rootless(self.client.info(), os.environ.get("ASU_BUILD_ENGINE_ID"))
        return {
            "Version": self.client.version().get("Version"),
            "Engine": "approved-rootless-docker",
        }


def verify_runtime_limits(container):
    """Check kernel controls after start; inspect declarations alone are insufficient."""
    expected = {
        "cpu.max": "400000 100000",
        "cpuset.cpus.effective": "0-3",
        "memory.max": str(MEMORY),
        "memory.swap.max": "0",
        "pids.max": "2048",
    }
    observed = {}
    for name, value in expected.items():
        code, output = container.exec_run(
            ["cat", "/sys/fs/cgroup/" + name], demux=True, user="1000:1000"
        )
        raw = output[0].decode().strip() if output[0] else ""
        if code or raw != value:
            raise EngineError("Kernel resource control differs: " + name)
        observed[name] = raw
    code, output = container.exec_run(
        ["cat", "/proc/self/status"], demux=True, user="1000:1000"
    )
    status = (
        dict(
            line.split(":", 1)
            for line in output[0].decode().splitlines()
            if ":" in line
        )
        if output[0]
        else {}
    )
    if (
        code
        or int(status.get("CapEff", "-1").strip(), 16) != 0
        or status.get("NoNewPrivs", "").strip() != "1"
        or status.get("Uid", "").split() != ["1000"] * 4
    ):
        raise EngineError("Kernel process privilege controls differ")
    return observed


def wait_for_global_lock(container):
    """PID1 owns the shared lock independently of the API/RQ worker lifetime."""
    import time

    deadline = time.monotonic() + 1200
    while time.monotonic() < deadline:
        container.reload()
        if container.status != "running":
            raise EngineError(
                "Container lock holder exited; verify timeout/flock binaries and mapped-UID lock ACL"
            )
        code, output = container.exec_run(
            ["cat", "/builder/.asu-lock-held"], demux=True, user="1000:1000"
        )
        if code == 0 and output[0] and output[0].decode() == container.asu_lock_token:
            status, actual = container.exec_run(
                ["stat", "-Lc", "%d:%i", "/build-lock/.build.lock"],
                demux=True,
                user="1000:1000",
            )
            if (
                status
                or not actual[0]
                or actual[0].decode().strip() != container.asu_lock_identity
            ):
                raise EngineError(
                    "Container lock does not reference the shared host inode"
                )
            return
        time.sleep(0.25)
    raise EngineError("Timed out waiting for the global build lock")
