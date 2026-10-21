#!/usr/bin/env python3
"""Operator-only native ImageBuilder smoke; dry validated plan unless --run."""
import argparse
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import subprocess
import tarfile
import tempfile
import time

HERE = Path(__file__).resolve().parent
LOCK = '/home/valuxin/dev/owrt/ax6000-packages-build/work/.build.lock'
MIB = 1024**2
LABEL = 'io.valujin.ax6000-asu.operator-smoke'
MEMORY = 10 * 1024**3
HOLDER = ['timeout', '--foreground', '--kill-after=10s', '1200', 'flock', '-x', '/build-lock/.build.lock',
          '/bin/sh', '-ec', 'printf %s "$ASU_LOCK_TOKEN" > /builder/.smoke-lock-held; exec sleep 86400']
CAP_SCRIPT = r'''set -eu
for x in cpu.max cpuset.cpus.effective memory.max memory.swap.max pids.max; do printf '%s=%s\n' "$x" "$(cat /sys/fs/cgroup/$x)"; done
cat /proc/self/status
'''


def require(condition, message):
    if not condition:
        raise ValueError(message)


def module(filename, name):
    spec = importlib.util.spec_from_file_location(name, filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


builder = module(HERE / 'builder_image.py', 'smoke_builder_image')
promotion = module(HERE / 'promote.py', 'smoke_promotion')


def identity(profile):
    firmware = profile['firmware']
    result = {'build_id': profile['build_id'], 'source_commit': firmware['commit'],
              'kernel_version': firmware['kernel_version'], 'architecture': firmware['architecture'],
              'target': 'mediatek/filogic'}
    if profile.get('package_manager', 'opkg') == 'apk':
        result['package_manager'] = 'apk'
    return result


def record(path, directory):
    path = promotion.regular(path, 1024**3)
    name = path.relative_to(Path(directory)).as_posix()
    return {'path': name, 'size': path.stat().st_size, 'sha256': builder.sha256(path)}


def native_source_file(recorded, prefix, source, checksum, *, required_relative=None, executable=False):
    """Map a reviewed proof namespace into the actual source without aliases."""
    require(isinstance(recorded, str) and isinstance(prefix, str), 'Native source paths must be strings')
    for value in (recorded, prefix, str(source)):
        path = PurePosixPath(value)
        require(path.is_absolute() and value != '/' and not value.startswith('//')
                and str(path) == value and '..' not in path.parts and '\x00' not in value,
                'Native source paths/prefix must be canonical absolute paths')
    recorded_path, proof_prefix = PurePosixPath(recorded), PurePosixPath(prefix)
    require(recorded_path.is_relative_to(proof_prefix) and recorded_path != proof_prefix,
            'Native proof path is outside its explicit source prefix')
    relative = recorded_path.relative_to(proof_prefix).as_posix()
    require(required_relative is None or relative == required_relative, 'Native tool has an unexpected source-relative suffix')
    actual = Path(source) / relative
    if executable:
        actual = promotion.pinned_tool(actual, checksum)
    else:
        actual = promotion.regular(actual, 64 * MIB)
        require(builder.SHA.fullmatch(checksum or '') and builder.sha256(actual) == checksum,
                'Native source file SHA256 differs')
    return actual, {'recorded_path': recorded, 'source_relative_path': relative,
                    'actual_path': str(actual), 'sha256': checksum}


def make_command(operation, layout, packages):
    require(operation in ('info', 'manifest', 'image') and layout in ('stock', 'mtkuboot', 'ubootmod'), 'Invalid smoke operation/layout')
    require(packages and all(builder.NAME.fullmatch(name) for name in packages), 'Unsafe actual package name')
    command = ['nice', '-n', '19', 'ionice', '-c', '3', 'make', '-s', operation]
    if operation != 'info':
        command += ['PROFILE=xiaomi_redmi-router-ax6000-' + layout,
                    'PACKAGES=' + ' '.join(sorted(set(packages))) + ' -tailscale']
    if operation == 'image':
        command += ['FILES=/builder/smoke-files', 'BIN_DIR=/builder/smoke-out']
    return command


def validate_manifest(actual, defaults, controls, kernel, manager):
    require(actual and set(defaults) <= set(actual) and 'tailscale' not in actual, 'Smoke manifest drops native defaults or adds Tailscale')
    for name, version in actual.items():
        require(name in controls and controls[name]['Version'] == version, 'Unapproved emitted package/version: ' + name)
    require(actual.get('kernel') == kernel, 'Emitted kernel ABI differs')
    require((manager == 'apk' and 'opkg' not in actual and bool({'apk-openssl', 'apk-mbedtls', 'apk'} & set(actual)))
            or (manager == 'opkg' and 'opkg' in actual and not any(name.startswith('apk') for name in actual)), 'Emitted package manager differs')
    require(not any(name.startswith(('kmod-mt76', 'kmod-mt7915', 'kmod-mt7986-firmware')) for name in actual), 'Foreign radio stack in smoke image')


def validate_caps(content):
    lines = content.splitlines()
    controls = dict(line.split('=', 1) for line in lines if '=' in line and ':' not in line)
    require(controls == {'cpu.max': '400000 100000', 'cpuset.cpus.effective': '0-3',
                         'memory.max': str(MEMORY), 'memory.swap.max': '0', 'pids.max': '2048'}, 'Actual kernel resource limits differ')
    status = dict(line.split(':', 1) for line in lines if ':' in line)
    require(status.get('Uid', '').split() == ['1000'] * 4 and status.get('Gid', '').split() == ['1000'] * 4
            and status.get('NoNewPrivs', '').strip() == '1'
            and int(status.get('CapEff', '-1').strip(), 16) == 0, 'Actual privilege controls differ')
    return controls


def validate_hardkill_proof(proof, lock_stat):
    require(proof.get('schema_version') == 1 and proof.get('kind') == 'ax6000-rootless-lock-hardkill'
            and proof.get('ok') is True and proof.get('engine_id') == builder.ROOTLESS_ENGINE
            and proof.get('lock_device') == lock_stat.st_dev and proof.get('lock_inode') == lock_stat.st_ino
            and proof.get('held_after_worker_death') is True and proof.get('released_after_container_death') is True,
            'Reviewed hard-kill lock proof is missing or names a different engine/inode')


def compare_native_root(actual, native):
    for group in ('modules', 'firmware', 'repository_files'):
        for path, expected in native.get(group, {}).items():
            observed = actual.get(group, {}).get(path, {})
            require(observed.get('sha256') == expected.get('sha256')
                    and all(observed.get(key) == expected[key] for key in ('size', 'mode') if key in expected),
                    'Smoke root differs from independently inspected native ' + group + ': ' + path)
    for path, expected in (native.get('optional_features') or {}).get('files', {}).items():
        observed = (actual.get('optional_features') or {}).get('files', {}).get(path, {})
        require(observed.get('sha256') == expected.get('sha256')
                and all(observed.get(key) == expected[key] for key in ('size', 'mode') if key in expected),
                'Smoke optional feature differs from independently inspected native image: ' + path)


def client_command(arguments, asset=None):
    command = ['/usr/bin/docker', '--host', builder.ROOTFUL_SOCKET, 'run', '--rm', '--pull=never',
               '--network=none', '--read-only', '--user=2000:2000', '--cap-drop=ALL', '--security-opt=no-new-privileges',
               '--cpus=1', '--memory=2g', '--memory-swap=2g', '--pids-limit=128',
               '--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=16m', '--env=HOME=/tmp', '--entrypoint=/bin/sh',
               '--label=' + LABEL + '-client=true',
               '--mount=type=bind,src=/usr/bin/docker,dst=/usr/bin/docker,readonly',
               '--mount=type=bind,src=' + builder.ROOTLESS_SOCKET + ',dst=/run/ax6000-build/docker.sock']
    if asset is not None:
        asset = promotion.regular(asset, 2 * MIB)
        require(',' not in str(asset), 'Unsafe asset bind path')
        command += ['--mount=type=bind,src=' + str(asset) + ',dst=/assets/input.tar,readonly']
    return command + [builder.BASE_IMAGE, '-ec', builder.CLIENT_GUARD, '--', builder.ROOTLESS_ENGINE, *arguments]


def client(arguments, verifier, destination=None, cap=8 * MIB, timeout=120, asset=None):
    env_keys = ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH', 'DOCKER_CONFIG', 'DOCKER_API_VERSION')
    # Native bounded runner inherits our environment; no ambient host/context can
    # redirect explicit sockets. Remove only during this synchronous invocation.
    previous = {key: os.environ.pop(key) for key in env_keys if key in os.environ}
    try:
        return verifier.run_bounded(client_command(arguments, asset), cap, timeout=timeout, destination=destination)
    finally:
        os.environ.update(previous)


def container_command(image_id, token):
    require(re.fullmatch(r'sha256:[a-f0-9]{64}', image_id) and re.fullmatch(r'[a-f0-9]{32}', token), 'Unsafe image/token')
    return ['container', 'create', '--pull=never', '--network=none', '--user=1000:1000',
            '--cap-drop=ALL', '--security-opt=no-new-privileges', '--cpu-period=100000', '--cpu-quota=400000',
            '--cpuset-cpus=0-3', '--memory=10g', '--memory-swap=10g', '--pids-limit=2048',
            '--label=' + LABEL + '=true', '--env=ASU_LOCK_TOKEN=' + token,
            '--mount=type=bind,src=' + LOCK + ',dst=/build-lock/.build.lock,readonly',
            '--entrypoint=timeout', image_id, *HOLDER[1:]]


def assert_container(inspect, image_id):
    host = inspect['HostConfig']
    expected = {'CpuPeriod': 100000, 'CpuQuota': 400000, 'CpusetCpus': '0-3', 'Memory': MEMORY,
                'MemorySwap': MEMORY, 'PidsLimit': 2048, 'Privileged': False, 'NetworkMode': 'none'}
    require(all(host.get(key) == value for key, value in expected.items()), 'Container resource declarations differ')
    require({value.upper() for value in host.get('CapDrop') or []} == {'ALL'} and not host.get('CapAdd')
            and any(value.split('=')[0].split(':')[0] == 'no-new-privileges' for value in host.get('SecurityOpt') or []),
            'Container capability restrictions differ')
    require(inspect['Config'].get('User') == '1000:1000' and inspect.get('Image') == image_id
            and inspect['Config'].get('Labels', {}).get(LABEL) == 'true', 'Container image/user/ownership differs')
    require(len(inspect.get('Mounts', [])) == 1 and inspect['Mounts'][0].get('Source') == LOCK
            and inspect['Mounts'][0].get('Destination') == '/build-lock/.build.lock'
            and inspect['Mounts'][0].get('RW') is False, 'Container must mount only the shared lock read-only')


def wait_lock(container_id, token, lock_stat, verifier):
    deadline = time.monotonic() + 1190
    while time.monotonic() < deadline:
        inspect = json.loads(client(['container', 'inspect', container_id], verifier))[0]
        require(inspect['State'].get('Running') is True, 'Independent PID1 lock holder exited')
        # Do not use a failing docker-exec call while waiting: bounded helper treats
        # nonzero commands as fatal, and missing marker is expected before flock.
        marker = client(['container', 'exec', '--user=1000:1000', container_id, '/bin/sh', '-ec',
                         'if test -f /builder/.smoke-lock-held; then cat /builder/.smoke-lock-held; fi'], verifier).decode()
        if marker == token:
            inode = client(['container', 'exec', '--user=1000:1000', container_id,
                            'stat', '-Lc', '%d:%i', '/build-lock/.build.lock'], verifier).decode().strip()
            require(inode == f'{lock_stat.st_dev}:{lock_stat.st_ino}', 'PID1 holds a different build-lock inode')
            return
        require(not marker, 'Unexpected lock nonce')
        time.sleep(2)
    raise ValueError('Timed out waiting for the native/global build lock')


def overlay_tar(overlay, path):
    with tarfile.open(path, 'w') as archive:
        for name, value in sorted(overlay.items()):
            relative = PurePosixPath(name)
            require(str(relative) == name and not relative.is_absolute() and '..' not in relative.parts, 'Unsafe overlay path')
            data = base64.b64decode(value['content_base64'], validate=True)
            require(hashlib.sha256(data).hexdigest() == value['sha256'] and value['mode'] in (0o644, 0o755), 'Overlay hash/mode differs')
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode = len(data), value['mode']
            entry.uid = entry.gid = 1000
            archive.addfile(entry, io.BytesIO(data))
    path.chmod(0o444)


def unpack_outputs(archive, destination):
    require(not destination.exists(), 'Output extraction destination already exists')
    with tarfile.open(archive, 'r:') as tar:
        members, names, total = [], set(), 0
        for member in tar:
            raw = member.name.removeprefix('./').rstrip('/')
            if raw in ('', '.') and member.isdir():
                continue
            name = PurePosixPath(raw)
            require(str(name) == raw and not name.is_absolute() and '..' not in name.parts
                    and len(name.parts) <= 4 and raw not in names, 'Unsafe/duplicate exported output path')
            require(member.isfile() or member.isdir(), 'Exported output links/specials forbidden')
            total += member.size if member.isfile() else 0
            names.add(raw)
            require(len(names) <= 1000 and total <= 1024**3, 'Exported output exceeds limits')
            member.name = raw
            members.append(member)
        destination.mkdir()
        tar.extractall(destination, members=members, filter='data')


def load_context(args, work):
    profile = promotion.read_json(args.profile)
    approval = builder.validate_inputs(args.archive, args.archive_sha256, args.builder_approval,
                                      args.builder_approval_sha256, args.profile, args.public_key)
    require(approval['cohort'] == args.cohort, 'Approval/cohort mismatch')
    native = promotion.read_json(args.native_evidence, args.native_evidence_sha256)
    require(native.get('ok') is True and native.get('build_id') == profile['build_id']
            and native.get('source_commit') == profile['firmware']['commit']
            and native.get('kernel_abi') == profile['firmware']['kernel_version'], 'Native proof generation differs')
    require(set(native.get('layouts', {})) == ({'stock'} if args.cohort == '66' else {'stock', 'mtkuboot', 'ubootmod'}), 'Native proof layout coverage differs')
    loaded = promotion.read_json(args.builder_load_receipt, args.builder_load_receipt_sha256)
    expected = {'kind': 'ax6000-imagebuilder-image-load', 'image_id': args.image_id, 'archive_sha256': args.archive_sha256,
                'attestation_sha256': approval['attestation_sha256'], 'loaded_engine_id': builder.ROOTLESS_ENGINE,
                'approval_receipt_sha256': args.builder_approval_sha256, 'cohort': args.cohort, 'build_id': profile['build_id'],
                'source_commit': profile['firmware']['commit'], 'uid': 1000, 'gid': 1000, 'flock_timeout_available': True}
    require(all(loaded.get(key) == value for key, value in expected.items()) and re.fullmatch(r'sha256:[a-f0-9]{64}', args.image_id), 'Loaded-image receipt differs')
    snapshot = promotion.regular(args.snapshot_manifest)
    require(builder.sha256(snapshot) == args.snapshot_sha256 and builder.SHA.fullmatch(args.snapshot_sha256), 'Signed snapshot manifest SHA differs')
    snapshot_data = promotion.read_json(snapshot)
    require(snapshot_data.get('schema_version') == 1 and snapshot_data.get('profile_id') == profile.get('id')
            and snapshot_data.get('build_id') == profile['build_id']
            and snapshot_data.get('kernel_version') == profile['firmware']['kernel_version'], 'Signed snapshot generation differs')
    require((args.cohort == '66' and snapshot_data.get('cohort') == '66')
            or (args.cohort != '66' and snapshot_data.get('channel') == args.cohort.removeprefix('612-')), 'Signed snapshot cohort differs')
    usign = promotion.pinned_tool(args.usign, args.usign_sha256)
    subprocess.run([str(usign), '-V', '-m', str(snapshot), '-p', str(promotion.regular(args.public_key)),
                    '-x', str(promotion.regular(args.snapshot_signature))], check=True, timeout=60,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    source = Path(args.source).absolute()
    require(subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip() == profile['firmware']['commit'], 'Native source commit differs')
    tree = builder.unpack(args.archive, Path(work) / 'unpacked')
    builder.scan_tree(tree, approval)
    attestation = promotion.read_json(tree / 'ax6000-imagebuilder.json')
    require(attestation.get('identity') == identity(profile), 'Archive attestation/package manager differs')
    controls, packages = {}, {}
    for item in attestation.get('packages', []):
        control = item['control']
        name = control['Package']
        require(name not in controls and builder.NAME.fullmatch(name), 'Invalid/duplicate native bank name')
        path = promotion.regular(tree / 'packages' / item['filename'], 256 * MIB)
        require(path.parent == tree / 'packages' and path.stat().st_size == item['size'] and builder.sha256(path) == item['sha256']
                and control['Version'] == item['version'], 'Native package bank bytes/control differ')
        controls[name], packages[name] = control, path
    require(controls and controls.get('kernel', {}).get('Version') == profile['firmware']['kernel_version'], 'Missing matching native bank')
    return {'profile': profile, 'approval': approval, 'native': native, 'loaded': loaded, 'tree': tree,
            'attestation': attestation, 'controls': controls, 'packages': packages, 'source': source}


def prepare_native(args, context, recipe):
    profile, native, source = context['profile'], context['native'], context['source']
    verifier = promotion.load_module(Path(recipe) / 'scripts/verify-firmware.py', 'smoke_native_verifier')
    overlay = promotion.rootfs_overlay(recipe, source, profile, native, context['attestation'])
    defaults = {}
    for layout, evidence in native['layouts'].items():
        manifest_record = evidence['root']['package_manifest']
        require(Path(manifest_record['filename']).name == manifest_record['filename'], 'Unsafe native manifest filename')
        manifest = promotion.regular(Path(args.raw) / 'bin/targets/mediatek/filogic' / manifest_record['filename'], 8 * MIB)
        require(builder.sha256(manifest) == manifest_record['sha256'], 'Actual native device manifest SHA differs')
        actual = verifier.device_manifest(manifest)
        require(set(actual) == set(evidence['root']['installed_packages']), 'Actual native installed package names differ')
        defaults[layout] = {name: version for name, version in actual.items() if name != 'tailscale'}
        validate_manifest(defaults[layout], defaults[layout], context['controls'], profile['firmware']['kernel_version'], profile.get('package_manager', 'opkg'))
    tools = {}
    proof_prefix = str(source) if args.native_source_prefix is None else args.native_source_prefix
    mapping = {'proof_source_prefix': proof_prefix, 'actual_source': str(source), 'tools': {}}
    for name in ('fwtool', 'unsquashfs4'):
        proof = native['trusted_tools'][name]
        path, tool_mapping = native_source_file(proof['path'], proof_prefix, source, proof['sha256'],
                                                required_relative='staging_dir/host/bin/' + name, executable=True)
        tools[name] = path
        mapping['tools'][name] = tool_mapping
    kernel, kernel_mapping = native_source_file(native['sysupgrade_input']['path'], proof_prefix, source,
                                                native['sysupgrade_input']['sha256'])
    require(kernel_mapping['source_relative_path'].endswith('/Image')
            and kernel_mapping['source_relative_path'] in {item['path'] for item in context['attestation']['context']},
            'Native uncompressed kernel path is not the independently attested source-relative Image')
    mapping['kernel'] = kernel_mapping
    configs = [context['tree'] / item['path'] for item in context['attestation']['context'] if item['path'].endswith('/.config')]
    require(len(configs) == 1, 'Ambiguous attested kernel configuration')
    context.update(verifier=verifier, overlay=overlay, defaults=defaults, tools=tools, kernel=kernel, kernel_config=configs[0].read_bytes(),
                   native_lock=promotion.read_json(Path(args.raw) / 'lock.json'), native_source_mapping=mapping)
    if profile.get('package_manager', 'opkg') == 'apk':
        require(args.apk and args.apk_sha256, 'APK smoke requires a pinned host APK decoder')
        context['apk'] = promotion.pinned_tool(args.apk, args.apk_sha256)
    return context


def inspect_artifacts(layout, directory, context, receipt_parent):
    verifier, profile, native = context['verifier'], context['profile'], context['native']
    artifacts = directory / 'artifacts'
    overview = promotion.read_json(artifacts / 'profiles.json')
    device = 'xiaomi_redmi-router-ax6000-' + layout
    require(overview.get('target') == 'mediatek/filogic' and device in overview.get('profiles', {}), 'Built profiles.json target/layout differs')
    candidates = [item for item in overview['profiles'][device].get('images', [])
                  if item.get('type') == 'sysupgrade' and item.get('filesystem') == 'squashfs']
    require(len(candidates) == 1, 'Expected exactly one actual sysupgrade image')
    image_record = candidates[0]
    require(Path(image_record['name']).name == image_record['name'], 'Unsafe actual image filename')
    image = promotion.regular(artifacts / image_record['name'], 128 * MIB)
    require(builder.sha256(image) == image_record['sha256'], 'Actual output image checksum differs')
    manifests = list(artifacts.glob('*.manifest'))
    require(len(manifests) == 1, 'Expected exactly one actual emitted image manifest')
    actual = verifier.device_manifest(manifests[0])
    preflight = verifier.device_manifest(directory / 'manifest.txt')
    validate_manifest(actual, context['defaults'][layout], context['controls'], profile['firmware']['kernel_version'], profile.get('package_manager', 'opkg'))
    require(actual == preflight, 'Actual emitted image manifest differs from preflight')
    metadata_path, stripped = directory / 'fwtool.json', directory / 'stripped-image'
    original_sha = builder.sha256(image)
    verifier.run_bounded([str(context['tools']['fwtool']), '-i', str(metadata_path), '-T', str(image)], image.stat().st_size,
                         destination=stripped, timeout=120, file_cap=64 * 1024)
    require(builder.sha256(image) == original_sha, 'Host fwtool modified input image')
    metadata = promotion.read_json(metadata_path)
    verifier.verify_metadata(metadata, layout, profile)
    expected_version = native['layouts'][layout]['metadata']['version']
    require(all(metadata['version'].get(key) == expected_version.get(key) for key in ('version', 'revision')), 'Image firmware version/revision differs from native')
    if layout == 'ubootmod':
        fit = verifier.extract_fit(stripped, directory, external=True)
        root = fit['root']['path']
    else:
        payload = verifier.extract_tar(stripped, layout, directory)
        fit = verifier.extract_fit(payload['kernel'], directory, external=False)
        root = payload['root']
    kernel = verifier.verify_kernel(fit['kernel']['path'], fit['kernel']['compression'], context['kernel'], directory / 'kernel.Image')
    require(kernel['sha256'] == native['layouts'][layout]['kernel']['sha256'], 'Smoke kernel differs from actual native kernel')
    dtb = verifier.verify_dtb(fit['fdt']['path'], layout)
    expected_files = {path: (base64.b64decode(item['content_base64'], validate=True), item['mode']) for path, item in context['overlay'].items()}
    kwargs = {'feature_lock': context['native_lock'], 'feature_source': context['source']}
    if profile.get('package_manager', 'opkg') == 'apk':
        kwargs['apk'] = context['apk']
    root_record = verifier.inspect_root(root, layout, context['tools']['unsquashfs4'], profile,
                                        context['controls'], context['packages'], expected_files,
                                        native['layouts'][layout]['root']['trusted_key_fingerprint'],
                                        context['kernel_config'], actual, **kwargs)
    compare_native_root(root_record, native['layouts'][layout]['root'])
    (directory / 'root-inspection.json').write_text(json.dumps({'root': root_record, 'device_tree': dtb, 'kernel': kernel}, indent=2, sort_keys=True) + '\n')
    return {'exit_codes': {'info': 0, 'manifest': 0, 'image': 0},
            'info': record(directory / 'info.txt', receipt_parent), 'manifest': record(manifests[0], receipt_parent),
            'image': record(image, receipt_parent), 'metadata': record(metadata_path, receipt_parent),
            'kernel_sha256': kernel['sha256'], 'profiles': record(artifacts / 'profiles.json', receipt_parent),
            'root_inspection': record(directory / 'root-inspection.json', receipt_parent)}


def run_layout(layout, output, args, context, lock_stat):
    verifier = context['verifier']
    directory = output / layout
    directory.mkdir()
    overlay_file = directory / 'overlay.tar'
    overlay_tar(context['overlay'], overlay_file)
    token = secrets.token_hex(16)
    created = client(container_command(args.image_id, token), verifier).decode().strip()
    require(re.fullmatch('[a-f0-9]{64}', created), 'Docker returned invalid container identity')
    try:
        observed = json.loads(client(['container', 'inspect', created], verifier))[0]
        assert_container(observed, args.image_id)
        client(['container', 'start', created], verifier)
        wait_lock(created, token, lock_stat, verifier)
        caps = client(['container', 'exec', '--user=1000:1000', created, '/bin/sh', '-ec', CAP_SCRIPT], verifier).decode()
        validate_caps(caps)
        (directory / 'runtime-controls.txt').write_text(caps)
        client(['container', 'exec', '--user=1000:1000', created, 'mkdir', '-p', '/builder/smoke-files', '/builder/smoke-logs'], verifier)
        client(['container', 'cp', '/assets/input.tar', created + ':/builder/smoke-overlay.tar'], verifier, asset=overlay_file)
        client(['container', 'exec', '--user=1000:1000', created, 'tar', '-xf', '/builder/smoke-overlay.tar', '-C', '/builder/smoke-files'], verifier)
        for operation in ('info', 'manifest', 'image'):
            command = ['container', 'exec', '--user=1000:1000', '--workdir=/builder', created,
                       '/bin/sh', '-ec', 'err=$1; shift; exec "$@" 2> "$err"', '--',
                       '/builder/smoke-logs/' + operation + '.stderr',
                       *make_command(operation, layout, context['defaults'][layout])]
            try:
                client(command, verifier, destination=directory / (operation + '.txt'), cap=64 * MIB, timeout=1150)
            finally:
                client(['container', 'exec', '--user=1000:1000', created, 'cat', '/builder/smoke-logs/' + operation + '.stderr'],
                       verifier, destination=directory / (operation + '.stderr'), cap=64 * MIB)
            if operation == 'info':
                require(('xiaomi_redmi-router-ax6000-' + layout) in (directory / 'info.txt').read_text(), 'Actual make info omits layout')
            if operation == 'manifest':
                preflight = verifier.device_manifest(directory / 'manifest.txt')
                validate_manifest(preflight, context['defaults'][layout], context['controls'], context['profile']['firmware']['kernel_version'], context['profile'].get('package_manager', 'opkg'))
        exported = directory / 'outputs.tar'
        client(['container', 'cp', created + ':/builder/smoke-out/.', '-'], verifier,
               destination=exported, cap=1024**3 + MIB, timeout=120)
        unpack_outputs(exported, directory / 'artifacts')
        return inspect_artifacts(layout, directory, context, output)
    finally:
        # Delete only this newly created ID; never reap other native/ASU containers.
        client(['container', 'rm', '--force', created], verifier)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('cohort', 'image-id', 'archive-sha256', 'builder-approval-sha256', 'builder-load-receipt-sha256',
                 'native-evidence-sha256', 'snapshot-sha256', 'usign-sha256', 'recipe-commit'):
        parser.add_argument('--' + name, required=True)
    for name in ('archive', 'profile', 'builder-approval', 'builder-load-receipt', 'native-evidence', 'snapshot-manifest',
                 'snapshot-signature', 'public-key', 'usign', 'source', 'raw', 'package-repository', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--apk', type=Path)
    parser.add_argument('--apk-sha256')
    parser.add_argument('--native-source-prefix', help='Canonical absolute source prefix recorded inside native proof (default: actual host source)')
    parser.add_argument('--run', action='store_true', help='Explicitly run actual rootless make operations; default prints validated plan')
    parser.add_argument('--lock-proof', type=Path)
    parser.add_argument('--lock-proof-sha256')
    args = parser.parse_args(argv)
    output = args.output.absolute()
    require(not output.exists() and not any(path.is_symlink() for path in (output, *output.parents)), 'Smoke output must be fresh and without symlink parents')
    with tempfile.TemporaryDirectory(prefix='asu-smoke-prepare-') as work:
        context = load_context(args, work)
        with promotion.recipe_modules(args.package_repository, args.recipe_commit) as recipe:
            require(not subprocess.check_output(['git', '-C', str(recipe), 'status', '--porcelain', '--untracked-files=all', '--', 'files']),
                    'Trusted recipe files/ assets must match their approved committed bytes')
            prepare_native(args, context, recipe)
            plan = {'make_commands_executed': False, 'image_id': args.image_id, 'identity': identity(context['profile']),
                    'archive_sha256': args.archive_sha256, 'attestation_sha256': context['approval']['attestation_sha256'],
                    'snapshot_sha256': args.snapshot_sha256, 'overlay_paths': sorted(context['overlay']),
                    'native_source_mapping': context['native_source_mapping'],
                    'layouts': {layout: {operation: make_command(operation, layout, packages)
                                        for operation in ('info', 'manifest', 'image')}
                                for layout, packages in context['defaults'].items()}}
            if not args.run:
                print(json.dumps(plan, indent=2, sort_keys=True))
                return
            require(args.lock_proof and args.lock_proof_sha256, '--run requires independently reviewed hard-kill lock proof and SHA')
            lock_stat = os.stat(LOCK)
            validate_hardkill_proof(promotion.read_json(args.lock_proof, args.lock_proof_sha256), lock_stat)
            os.nice(19)
            subprocess.run(['ionice', '-c', '3', '-p', str(os.getpid())], check=True)
            verifier = context['verifier']
            loaded = json.loads(client(['image', 'inspect', args.image_id], verifier))[0]
            require(loaded['Id'] == args.image_id and all(loaded['Config'].get('Labels', {}).get(key) == value
                    for key, value in builder.labels(context['approval'], args.builder_approval_sha256).items()), 'Actual rootless image labels/identity differ')
            output.mkdir(parents=True)
            (output / 'plan.json').write_text(json.dumps(plan, indent=2, sort_keys=True) + '\n')
            receipt = {'schema_version': 1, 'kind': 'ax6000-imagebuilder-smoke', 'identity': identity(context['profile']),
                       'archive_sha256': args.archive_sha256, 'attestation_sha256': context['approval']['attestation_sha256'],
                       'snapshot_sha256': args.snapshot_sha256, 'image_id': args.image_id,
                       'rootless_engine_id': builder.ROOTLESS_ENGINE, 'native_evidence_sha256': args.native_evidence_sha256,
                       'hardkill_lock_proof_sha256': args.lock_proof_sha256, 'lock_device': lock_stat.st_dev,
                       'lock_inode': lock_stat.st_ino, 'overlay_paths': sorted(context['overlay']), 'layouts': {}}
            receipt['native_source_mapping'] = context['native_source_mapping']
            for layout in sorted(context['defaults']):
                receipt['layouts'][layout] = run_layout(layout, output, args, context, lock_stat)
            (output / 'evidence.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
            print(json.dumps({'make_commands_executed': True, 'evidence': str(output / 'evidence.json'),
                              'sha256': builder.sha256(output / 'evidence.json'), 'catalog_promoted': False}, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit('ImageBuilder smoke refused: ' + str(error)) from error
