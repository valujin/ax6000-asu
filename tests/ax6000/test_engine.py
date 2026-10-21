import unittest
from asu.docker_engine import (
    EngineError,
    assert_rootless,
    assert_build_limits,
    verify_runtime_limits,
    wait_for_global_lock,
)


class EngineTests(unittest.TestCase):
    def test_rootful_and_wrong_identity_rejected(self):
        for opts in [[], ["name=seccomp,profile=builtin"]]:
            with self.assertRaises(EngineError):
                assert_rootless({"SecurityOptions": opts, "ID": "x"}, "x")
        with self.assertRaises(EngineError):
            assert_rootless(
                {"SecurityOptions": ["name=rootless"], "ID": "other"}, "approved"
            )
        assert_rootless(
            {"SecurityOptions": ["name=rootless"], "ID": "approved"}, "approved"
        )

    def test_kernel_limits_are_required_after_start(self):
        from unittest.mock import MagicMock

        container = MagicMock()
        values = [
            b"400000 100000",
            b"0-3",
            b"10737418240",
            b"0",
            b"2048",
            b"CapEff:\t0000000000000000\nNoNewPrivs:\t1\nUid:\t1000\t1000\t1000\t1000",
        ]
        container.exec_run.side_effect = [(0, (x, b"")) for x in values]
        self.assertEqual(verify_runtime_limits(container)["memory.swap.max"], "0")
        container.exec_run.side_effect = [(0, (b"max 100000", b""))]
        with self.assertRaises(EngineError):
            verify_runtime_limits(container)

    def test_lock_ready_nonce_and_inode_required(self):
        from unittest.mock import MagicMock

        container = MagicMock()
        container.status = "running"
        container.asu_lock_token = "new-token"
        container.asu_lock_identity = "1:234"
        container.exec_run.side_effect = [
            (0, (b"new-token", b"")),
            (0, (b"1:234\n", b"")),
        ]
        wait_for_global_lock(container)
        container.exec_run.side_effect = [
            (0, (b"new-token", b"")),
            (0, (b"1:999\n", b"")),
        ]
        with self.assertRaises(EngineError):
            wait_for_global_lock(container)
        container.status = "exited"
        with self.assertRaises(EngineError):
            wait_for_global_lock(container)

    def test_effective_caps_must_all_match(self):
        config = {
            "Config": {"User": "1000:1000"},
            "HostConfig": {
                "CpuPeriod": 100000,
                "CpuQuota": 400000,
                "CpusetCpus": "0-3",
                "Memory": 10 * 1024**3,
                "MemorySwap": 10 * 1024**3,
                "PidsLimit": 2048,
                "CapDrop": ["ALL"],
                "CapAdd": [],
                "Privileged": False,
                "SecurityOpt": ["no-new-privileges"],
                "NetworkMode": "asu-build",
            },
        }
        assert_build_limits(config)
        for key, value in [
            ("CpuQuota", 0),
            ("Memory", 0),
            ("Privileged", True),
            ("CapAdd", ["SYS_ADMIN"]),
        ]:
            with self.subTest(key=key), self.assertRaises(EngineError):
                assert_build_limits(
                    {**config, "HostConfig": {**config["HostConfig"], key: value}}
                )


if __name__ == "__main__":
    unittest.main()
