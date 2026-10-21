#!/usr/bin/python3
"""Small, independently testable checks; never changes Docker or account state."""
import ctypes
import ctypes.util
import json
import os
import pathlib
import pwd
import re
import sys

MEMORY = 10 * 1024**3
CONTROLLERS = {'cpu', 'cpuset', 'memory', 'pids', 'io'}


def drop_worker_credentials(uid, gid, supplementary):
    """Match Docker's explicit user:group and group_add, including empty groups."""
    os.setgroups(supplementary)
    os.setgid(gid)
    os.setuid(uid)


def worker_lock_probe(path, uid, gid, lock_gid):
    """Run credential-equivalent positive/negative probes in isolated children."""
    if os.geteuid() != 0:
        raise ValueError('Credential-equivalent probes require root')
    for groups, expect_allowed in [([], False), ([lock_gid], True)]:
        child = os.fork()
        if child == 0:
            try:
                drop_worker_credentials(uid, gid, groups)
                try:
                    fd = os.open(path, os.O_RDWR)
                except PermissionError:
                    allowed = False
                else:
                    os.close(fd)
                    allowed = True
                os._exit(0 if allowed == expect_allowed else 1)
            except BaseException:
                os._exit(2)
        _, status = os.waitpid(child, 0)
        if status != 0:
            raise ValueError(f'Worker lock probe failed: supplemental groups={groups}, status={status}')


def apt_plan(text):
    installed = []
    for line in text.splitlines():
        if line.startswith(('Remv ', 'Purg ')):
            raise ValueError('APT proposes package removal')
        if line.startswith('Inst '):
            parts = line.split()
            if parts[1].split(':')[0] not in {'uidmap', 'libsubid4'}:
                raise ValueError(f'Unexpected APT dependency: {parts[1]}')
            if len(parts) > 2 and parts[2].startswith('['):
                raise ValueError('APT proposes upgrading an installed package')
            installed.append(parts[1])
    if not re.search(r'^0 upgraded, \d+ newly installed, 0 to remove', text, re.M):
        raise ValueError('Unrecognized or unsafe APT summary')
    return installed


def allocate_subids(texts):
    ranges = []
    for text in texts:
        for line in text.splitlines():
            if line.strip():
                _, start, count = line.split(':')
                ranges.append((int(start), int(start) + int(count)))
    start = 131072
    while any(start < end and start + 65536 > begin for begin, end in ranges):
        start += 65536
    if start + 65536 >= 2**32:
        raise ValueError('No subordinate ID range available')
    return start


def info_check(info, expected_id=None):
    if not any(x.split(',')[0] == 'name=rootless' for x in info['SecurityOptions']):
        raise ValueError('Docker daemon is not rootless')
    if info.get('CgroupVersion') != '2' or info.get('CgroupDriver') != 'systemd':
        raise ValueError('Rootless Docker lacks systemd cgroup v2')
    if not info.get('ID') or (expected_id and info['ID'] != expected_id):
        raise ValueError('Unexpected Docker engine identity')
    for key in ('MemoryLimit', 'SwapLimit', 'CpuCfsQuota', 'CPUSet', 'PidsLimit'):
        if info.get(key) is not True:
            raise ValueError(f'Docker does not report working {key}')
    return info['ID']


def caps_check(text):
    values = dict(line.split('=', 1) for line in text.splitlines() if '=' in line)
    expected = {'cpuset.cpus.effective': '0-3', 'memory.max': str(MEMORY),
                'memory.swap.max': '0', 'pids.max': '2048'}
    for key, value in expected.items():
        if values.get(key) != value:
            raise ValueError(f'{key}: expected {value}, got {values.get(key)}')
    quota, period = values['cpu.max'].split()
    if int(quota) != 4 * int(period):
        raise ValueError('CPU quota is not exactly four CPUs')


def grant_traverse(path, uid):
    """Preserve the existing ACL and add only named-user search permission.

    libacl is an existing Ubuntu runtime dependency; no acl package is installed.
    Refuse masks lacking x to avoid silently broadening existing ACL entries.
    """
    lib = ctypes.CDLL(ctypes.util.find_library('acl'), use_errno=True)
    for name, args, result in [
        ('acl_get_file', [ctypes.c_char_p, ctypes.c_int], ctypes.c_void_p),
        ('acl_to_text', [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ssize_t)], ctypes.c_void_p),
        ('acl_from_text', [ctypes.c_char_p], ctypes.c_void_p),
        ('acl_valid', [ctypes.c_void_p], ctypes.c_int),
        ('acl_set_file', [ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p], ctypes.c_int),
        ('acl_free', [ctypes.c_void_p], ctypes.c_int),
    ]:
        fn = getattr(lib, name)
        fn.argtypes, fn.restype = args, result
    acl = lib.acl_get_file(os.fsencode(path), 0x8000)
    if not acl:
        raise OSError(ctypes.get_errno(), 'acl_get_file')
    ptr = lib.acl_to_text(acl, None)
    if not ptr:
        lib.acl_free(acl)
        raise OSError(ctypes.get_errno(), 'acl_to_text')
    text = ctypes.string_at(ptr).decode()
    lib.acl_free(ptr)
    lib.acl_free(acl)
    lines = text.strip().splitlines()
    # Numeric IDs avoid NSS-dependent parsing. Existing named permission must match.
    try:
        label = pwd.getpwuid(uid).pw_name
    except KeyError:
        label = str(uid)
    target = f'user:{label}:--x'
    existing = [x for x in lines if x.startswith((f'user:{uid}:', f'user:{label}:'))]
    if existing and (len(existing) != 1 or existing[0].split(':', 2)[2] != '--x'):
        raise ValueError('Unexpected existing builder ACL')
    mask = next((x for x in lines if x.startswith('mask::')), None)
    group = next(x for x in lines if x.startswith('group::'))
    if 'x' not in (mask or group):
        raise ValueError('Existing ACL mask lacks traversal; manual review needed')
    if not mask:
        lines.append('mask::' + group.split('::', 1)[1])
    if not existing:
        lines.append(target)
    updated = lib.acl_from_text(('\n'.join(lines) + '\n').encode())
    if not updated:
        raise OSError(ctypes.get_errno(), 'acl_from_text')
    try:
        if lib.acl_valid(updated) or lib.acl_set_file(os.fsencode(path), 0x8000, updated):
            raise OSError(ctypes.get_errno(), 'setting traversal ACL')
    finally:
        lib.acl_free(updated)


if __name__ == '__main__':
    command = sys.argv[1]
    if command == 'apt':
        print(','.join(apt_plan(sys.stdin.read())))
    elif command == 'subids':
        print(allocate_subids([pathlib.Path(x).read_text() for x in sys.argv[2:]]))
    elif command == 'info':
        print(info_check(json.load(sys.stdin), sys.argv[2] if len(sys.argv) > 2 else None))
    elif command == 'caps':
        caps_check(sys.stdin.read())
    elif command == 'traverse':
        grant_traverse(sys.argv[2], int(sys.argv[3]))
    elif command == 'worker-lock':
        worker_lock_probe(sys.argv[2], *(int(x) for x in sys.argv[3:6]))
    else:
        raise ValueError('Unknown command')
