#!/usr/bin/python3
import os
import pathlib
import tempfile
import unittest
from unittest.mock import patch, call

import host_checks as checks


class SafetyChecks(unittest.TestCase):
    def test_forked_lock_probe_rejects_missing_or_overbroad_access(self):
        credentials = {}

        def simulated_drop(uid, gid, supplementary):
            credentials['groups'] = supplementary

        def simulated_open(path, flags):
            if credentials['groups'] != [995]:
                raise PermissionError(path)
            return os.dup(1)

        # Exercise real child/exit/wait handling without changing host credentials.
        with patch.object(checks.os, 'geteuid', return_value=0), patch.object(checks, 'drop_worker_credentials', side_effect=simulated_drop):
            with patch.object(checks.os, 'open', side_effect=simulated_open):
                checks.worker_lock_probe('/simulated/lock', 2000, 2000, 995)
            with patch.object(checks.os, 'open', side_effect=lambda *args: os.dup(1)):
                with self.assertRaises(ValueError):
                    checks.worker_lock_probe('/simulated/lock', 2000, 2000, 995)
            with patch.object(checks.os, 'open', side_effect=PermissionError):
                with self.assertRaises(ValueError):
                    checks.worker_lock_probe('/simulated/lock', 2000, 2000, 995)

    def test_worker_credentials_explicitly_clear_or_add_supplementary_groups(self):
        with patch.object(checks.os, 'setgroups') as groups, patch.object(checks.os, 'setgid') as gid, patch.object(checks.os, 'setuid') as uid:
            ordered = unittest.mock.Mock()
            ordered.attach_mock(groups, 'groups')
            ordered.attach_mock(gid, 'gid')
            ordered.attach_mock(uid, 'uid')
            checks.drop_worker_credentials(2000, 2000, [995])
            self.assertEqual(ordered.mock_calls, [call.groups([995]), call.gid(2000), call.uid(2000)])
            ordered.reset_mock()
            checks.drop_worker_credentials(2000, 2000, [])
            self.assertEqual(ordered.mock_calls, [call.groups([]), call.gid(2000), call.uid(2000)])

    def test_apt_only_required_new_dependencies(self):
        plan = 'Inst libsubid4 (1.0 Ubuntu)\nInst uidmap (1.0 Ubuntu)\n0 upgraded, 2 newly installed, 0 to remove and 8 not upgraded.\n'
        self.assertEqual(checks.apt_plan(plan), ['libsubid4', 'uidmap'])
        for bad in ['Inst docker-ce (29 Ubuntu)\n', 'Inst uidmap [0.9] (1.0 Ubuntu)\n', 'Remv nginx\n']:
            with self.assertRaises(ValueError):
                checks.apt_plan(bad + plan)
        with self.assertRaises(ValueError):
            checks.apt_plan('APT failed')

    def test_allocate_avoids_both_maps_and_partial_overlap(self):
        self.assertEqual(checks.allocate_subids(['alice:100000:65536', 'bob:196600:131080']), 327680)

    def test_identity_and_required_cgroup_features(self):
        good = dict(ID='dedicated', SecurityOptions=['name=rootless', 'name=seccomp,profile=builtin'], CgroupVersion='2', CgroupDriver='systemd')
        good.update({key: True for key in ['MemoryLimit', 'SwapLimit', 'CpuCfsQuota', 'CPUSet', 'PidsLimit']})
        self.assertEqual(checks.info_check(good, 'dedicated'), 'dedicated')
        for overrides in [dict(ID='production'), dict(SecurityOptions=['name=seccomp']), dict(CgroupVersion='1'), dict(CgroupDriver='none'), dict(MemoryLimit=False), dict(CPUSet=False)]:
            with self.assertRaises(ValueError):
                checks.info_check(good | overrides, 'dedicated')

    def test_live_kernel_cap_values_must_match(self):
        good = 'cpu.max=400000 100000\ncpuset.cpus.effective=0-3\nmemory.max=10737418240\nmemory.swap.max=0\npids.max=2048\n'
        checks.caps_check(good)
        for old, new in [('400000', 'max'), ('0-3', '0-7'), ('10737418240', 'max'), ('swap.max=0', 'swap.max=max'), ('2048', 'max')]:
            with self.assertRaises((ValueError, KeyError)):
                checks.caps_check(good.replace(old, new))

    def test_acl_preserves_owner_group_other_and_is_idempotent(self):
        # Keep all test artifacts inside the authorized deployment-host directory.
        with tempfile.TemporaryDirectory(dir=pathlib.Path(__file__).parent) as directory:
            os.chmod(directory, 0o750)
            checks.grant_traverse(directory, 65533)
            checks.grant_traverse(directory, 65533)
            checks.grant_traverse(directory, os.getuid())
            checks.grant_traverse(directory, os.getuid())
            self.assertEqual(os.stat(directory).st_mode & 0o777, 0o750)
            acl = os.getxattr(directory, 'system.posix_acl_access')
            self.assertTrue(acl)
        with tempfile.TemporaryDirectory(dir=pathlib.Path(__file__).parent) as directory:
            os.chmod(directory, 0o700)
            with self.assertRaises(ValueError):
                checks.grant_traverse(directory, 65533)


if __name__ == '__main__':
    unittest.main()
