#!/usr/bin/env python3
"""Operator-only, offline ImageBuilder image preparation and guarded import.

Default: validate approved inputs and print a plan. --build-load is the explicit
mutation switch. This module is never imported by the public ASU application.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import subprocess
import tarfile
import tempfile

BASE_IMAGE = 'sha256:2398ea9311ca86441bd2c5756646caf2b5831f5d2c2a63c2d86373d5c527e653'
BASE_TAG = 'ax6000-builder:20261012'
ROOTFUL_SOCKET = 'unix:///var/run/docker.sock'
ROOTLESS_SOCKET = '/run/user/2000/docker.sock'
ROOTLESS_ENGINE = 'c592b58c-bc7e-40a0-91b5-29d5b29387a1'
SHA = re.compile(r'[0-9a-f]{64}')
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9+_.-]{0,127}')
PROFILES = {'xiaomi_redmi-router-ax6000-' + x for x in ('stock', 'mtkuboot', 'ubootmod')}
LABEL_PREFIX = 'io.valujin.ax6000-asu.'
MAX_ARCHIVE = 16 * 1024**3
MAX_EXPANDED = 24 * 1024**3
MAX_MEMBERS = 200000
KEY_MARKERS = re.compile(rb'-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|openssh-key-v1\x00|untrusted comment:[^\n]{0,160}(?:secret|private) key', re.I)
USIGN_SECRET = re.compile(rb'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{139}=(?![A-Za-z0-9+/=])')


def require(value, message):
    if not value:
        raise ValueError(message)


def private_key_content(data):
    if KEY_MARKERS.search(data):
        return True
    # usign private keys have a 104-byte Ed/BK structure; signatures are 74 bytes
    # and public keys 42 bytes. Do not trust the editable untrusted-comment label.
    for match in USIGN_SECRET.finditer(data):
        decoded = base64.b64decode(match.group(), validate=True)
        if len(decoded) == 104 and decoded.startswith(b'EdBK'):
            return True
    return len(data) == 104 and data.startswith(b'EdBK')


def sha256(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def regular(path, max_size=MAX_ARCHIVE):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= max_size,
            'Expected bounded regular file: ' + str(path))
    return path


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON key: ' + key)
        result[key] = value
    return result


def load_pinned(path, expected_sha):
    require(SHA.fullmatch(expected_sha or '') is not None, 'Missing independently approved SHA256')
    path = regular(path, 8 * 1024**2)
    require(sha256(path) == expected_sha, 'Approval receipt hash differs')
    return json.loads(path.read_text(), object_pairs_hook=unique_object)


def validate_inputs(archive, archive_sha, proof_path, proof_sha, profile_path, public_key_path):
    archive = regular(archive)
    require(SHA.fullmatch(archive_sha or '') is not None and sha256(archive) == archive_sha,
            'ImageBuilder archive hash differs')
    proof = load_pinned(proof_path, proof_sha)
    require(proof.get('schema_version') == 1 and proof.get('kind') == 'ax6000-imagebuilder-approval',
            'Wrong independently reviewed verification receipt schema')
    required_true = ('approved', 'source_context_verified', 'native_bank_verified',
                     'signatures_verified', 'private_keys_absent')
    require(all(proof.get(key) is True for key in required_true), 'ImageBuilder has incomplete independent verification')
    require(proof.get('archive_sha256') == archive_sha and proof.get('archive_size') == archive.stat().st_size,
            'Verification receipt names a different archive')
    for field in ('profile_sha256', 'public_key_sha256', 'attestation_sha256', 'verification_result_sha256'):
        require(SHA.fullmatch(proof.get(field, '')) is not None, 'Missing proof digest: ' + field)
    profile_path, public_key_path = regular(profile_path, 8 * 1024**2), regular(public_key_path, 8192)
    require(sha256(profile_path) == proof['profile_sha256'] and sha256(public_key_path) == proof['public_key_sha256'],
            'Profile or production public key differs from independent proof')
    public_key = public_key_path.read_bytes().splitlines()
    require(len(public_key) == 2 and public_key[0].startswith(b'untrusted comment:'), 'Expected production public usign key')
    try:
        payload = base64.b64decode(public_key[1], validate=True)
    except ValueError as error:
        raise ValueError('Invalid public usign key encoding') from error
    require(len(payload) == 42 and payload.startswith(b'Ed'), 'Not a public usign key')
    profile = json.loads(profile_path.read_text(), object_pairs_hook=unique_object)
    cohort = proof.get('cohort')
    require(cohort in ('66', '612-recommended', '612-latest'), 'Wrong cohort')
    require(NAME.fullmatch(proof.get('build_id', '')) is not None, 'Unsafe build ID')
    require(re.fullmatch('[0-9a-f]{40}', proof.get('source_commit', '')) is not None, 'Invalid source commit')
    require(re.fullmatch(r'6\.(6|12)\.\d+~[0-9a-f]{32}-r\d+', proof.get('kernel_version', '')) is not None,
            'Invalid exact kernel ABI')
    require(proof['kernel_version'].startswith('6.6.' if cohort == '66' else '6.12.'), 'Kernel ABI/cohort mismatch')
    require(proof.get('package_manager') == ('opkg' if cohort == '66' else 'apk'), 'Package manager/cohort mismatch')
    require(isinstance(proof.get('profiles'), list) and proof['profiles'] and len(set(proof['profiles'])) == len(proof['profiles'])
            and set(proof['profiles']) <= PROFILES, 'Invalid layout inventory')
    require(cohort != '66' or proof['profiles'] == ['xiaomi_redmi-router-ax6000-stock'], '6.6 accepts only stock layout')
    firmware = profile.get('firmware', {})
    require(profile.get('build_id') == proof['build_id'] and firmware.get('commit') == proof['source_commit']
            and firmware.get('kernel_version') == proof['kernel_version'], 'Profile generation/source/kernel mismatch')
    require(firmware.get('target') == 'mediatek' and firmware.get('subtarget') == 'filogic'
            and firmware.get('architecture') == 'aarch64_cortex-a53', 'Foreign target/architecture')
    require(profile.get('asu', {}).get('enabled') is True, 'Profile does not enable ASU')
    require(profile.get('imagebuilder', {}).get('sha256') == archive_sha
            and profile['imagebuilder'].get('size') == archive.stat().st_size, 'Profile ImageBuilder metadata differs')
    return proof


def unpack(archive, destination):
    """Strict internal links are allowed; link parents, aliases and specials are not."""
    archive, destination = Path(archive), Path(destination)
    require(not destination.exists(), 'Extraction destination already exists')
    temporary_tar = destination.parent / 'decompressed.tar'
    source = archive
    if archive.name.endswith('.zst'):
        require(not temporary_tar.exists(), 'Decompression destination exists')
        with temporary_tar.open('xb') as out:
            child = subprocess.Popen(['zstd', '--decompress', '--stdout', '--', str(archive)], stdout=subprocess.PIPE)
            try:
                total = 0
                while chunk := child.stdout.read(1024**2):
                    total += len(chunk)
                    require(total <= MAX_EXPANDED + MAX_MEMBERS * 2048, 'Decompressed archive exceeds bound')
                    out.write(chunk)
                require(child.wait() == 0, 'zstd decompression failed')
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
                child.stdout.close()
        source = temporary_tar
    with tarfile.open(source, 'r:*') as tar:
        members = []
        expanded = 0
        for member in tar:
            members.append(member)
            expanded += member.size if member.isfile() else 0
            require(len(members) <= MAX_MEMBERS and expanded <= MAX_EXPANDED, 'Archive expands beyond limit')
        paths, roots = {}, set()
        for member in members:
            path = PurePosixPath(member.name)
            require(path.parts and not path.is_absolute() and '..' not in path.parts
                    and str(path) == member.name.rstrip('/'), 'Unsafe archive member path')
            require(str(path) not in paths, 'Duplicate archive member')
            require(member.isfile() or member.isdir() or member.issym() or member.islnk(), 'Archive special file forbidden')
            require(not member.mode & 0o6000, 'Archive setuid/setgid file forbidden')
            paths[str(path)] = member
            roots.add(path.parts[0])
        require(len(roots) == 1, 'Archive must contain exactly one ImageBuilder root')
        for name, member in paths.items():
            path = PurePosixPath(name)
            for parent in path.parents:
                require(str(parent) not in paths or paths[str(parent)].isdir(), 'Archive writes through non-directory')
            if member.issym() or member.islnk():
                require(not member.linkname.startswith('/'), 'Absolute archive link forbidden')
                target = posixpath.join(str(path.parent), member.linkname) if member.issym() else member.linkname
                target = PurePosixPath(posixpath.normpath(target))
                require(target.parts and target.parts[0] == path.parts[0] and '..' not in target.parts, 'Archive link escapes root')
                if member.islnk():
                    require(str(target) in paths and paths[str(target)].isfile(), 'Hardlink must refer to regular member')
        destination.mkdir()
        tar.extractall(destination, members=members, filter='data')
    if source == temporary_tar:
        temporary_tar.unlink()
    tree = destination / next(iter(roots))
    require((tree / 'Makefile').is_file() and not (tree / 'Makefile').is_symlink(), 'ImageBuilder Makefile missing')
    return tree


def scan_tree(tree, proof):
    tree = Path(tree)
    files, total = 0, 0
    for path in tree.rglob('*'):
        relative = path.relative_to(tree)
        lower = path.name.lower()
        require(not ({'.ssh', '.gnupg', '.aws', '.git'} & set(relative.parts)), 'Private configuration directory in ImageBuilder')
        require(lower not in {'key-build', 'id_rsa', 'id_ed25519', 'id_ecdsa', '.netrc', '.env'}
                and not lower.endswith(('.key', '-private-key.pem', '.p12', '.pfx')),
                'Potential private key/credential filename in ImageBuilder: ' + str(relative))
        if path.is_symlink():
            require(path.resolve().is_relative_to(tree.resolve()), 'Extracted symlink escapes ImageBuilder')
            continue
        if not path.is_file():
            continue
        files += 1
        total += path.stat().st_size
        with path.open('rb') as stream:
            tail = b''
            while chunk := stream.read(1024**2):
                require(not private_key_content(tail + chunk), 'Private key marker in ImageBuilder: ' + str(relative))
                tail = chunk[-512:]
    attestation_path = regular(tree / 'ax6000-imagebuilder.json', 8 * 1024**2)
    require(sha256(attestation_path) == proof['attestation_sha256'], 'ImageBuilder attestation digest mismatch')
    metadata = json.loads(attestation_path.read_text(), object_pairs_hook=unique_object)
    expected = {'build_id': proof['build_id'], 'source_commit': proof['source_commit'], 'kernel_version': proof['kernel_version'],
                'architecture': 'aarch64_cortex-a53', 'target': 'mediatek/filogic'}
    if proof['package_manager'] == 'apk':
        expected['package_manager'] = 'apk'
    require(metadata.get('schema_version') == 1 and metadata.get('identity') == expected, 'ImageBuilder attestation identity mismatch')
    require(metadata.get('public_key_sha256') == proof['public_key_sha256'], 'ImageBuilder public-key attestation mismatch')
    contexts = metadata.get('context')
    require(isinstance(contexts, list) and contexts and len(contexts) <= MAX_MEMBERS, 'Missing native kernel/source context')
    seen = set()
    for item in contexts:
        path = PurePosixPath(item['path'])
        require(path.parts and not path.is_absolute() and '..' not in path.parts and str(path) == item['path']
                and str(path) not in seen, 'Unsafe/duplicate attested context path')
        seen.add(str(path))
        file = regular(tree / path)
        require(file.resolve().is_relative_to(tree.resolve()) and file.stat().st_size == item['size']
                and sha256(file) == item['sha256'], 'Attested native context differs: ' + str(path))
    require(any(x.endswith('/.config') for x in seen) and any(x.endswith('/Image') for x in seen)
            and any(x.endswith('.dtb') for x in seen)
            and {'tmp/.targetinfo', 'tmp/.packageinfo'} <= seen, 'Incomplete kernel/DTB/target/package context')
    require((tree / ('.config')).is_file(), 'ImageBuilder configuration missing')
    manager_file = 'repositories.conf' if proof['package_manager'] == 'opkg' else 'repositories'
    require((tree / manager_file).is_file(), 'ImageBuilder package manager differs')
    return {'regular_files': files, 'regular_bytes': total, 'context_files': len(contexts),
            'private_key_scan': 'prohibited names and markers; independent pinned approval covers complete archive'}


def labels(proof, proof_sha):
    return {LABEL_PREFIX + key: value for key, value in {
        'archive-sha256': proof['archive_sha256'], 'cohort': proof['cohort'], 'build-id': proof['build_id'],
        'proof-sha256': proof_sha, 'base-id': BASE_IMAGE,
        'attestation-sha256': proof['attestation_sha256'], 'source-commit': proof['source_commit'],
    }.items()}


def recipe(proof, proof_sha):
    result = [f'FROM {BASE_TAG}', 'COPY --chown=1000:1000 builder/ /builder/',
              'USER 1000:1000', 'WORKDIR /builder',
              'ENV HOME=/builder PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C',
              'ENTRYPOINT []', 'CMD ["sleep", "86400"]']
    result += ['LABEL ' + key + '=' + json.dumps(value) for key, value in sorted(labels(proof, proof_sha).items())]
    return '\n'.join(result) + '\n'


def checked_run(args, **kwargs):
    kwargs.setdefault('timeout', 1800)
    return subprocess.run(args, check=True, **kwargs)


def docker(args, **kwargs):
    env = dict(os.environ)
    for key in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH', 'DOCKER_CONFIG', 'DOCKER_API_VERSION'):
        env.pop(key, None)
    return checked_run(['/usr/bin/docker', '--host', ROOTFUL_SOCKET, *args], env=env, **kwargs)


def inspect_image(image):
    return json.loads(docker(['image', 'inspect', image], capture_output=True, text=True).stdout)[0]


def validate_image(base, image, expected_labels):
    require(base['Id'] == BASE_IMAGE, 'Base image ID differs')
    base_layers, layers = base['RootFS']['Layers'], image['RootFS']['Layers']
    require(layers[:len(base_layers)] == base_layers and len(layers) == len(base_layers) + 1,
            'Image layers are not the approved base plus one COPY layer')
    config = image['Config']
    require(config.get('User') == '1000:1000' and config.get('WorkingDir') == '/builder'
            and not config.get('Entrypoint') and config.get('Cmd') == ['sleep', '86400'], 'Unexpected image execution configuration')
    require(not config.get('Volumes') and not config.get('OnBuild'), 'Unexpected image volumes/build hooks')
    require(all(config.get('Labels', {}).get(key) == value for key, value in expected_labels.items()), 'Image labels differ from verified inputs')
    require(re.fullmatch(r'sha256:[0-9a-f]{64}', image.get('Id', '')) is not None, 'Invalid image identity')


# Guard occurs inside every client container, immediately before its requested API call.
# Arguments remain positional; archive/proof text is never interpolated as shell code.
CLIENT_GUARD = r'''set -eu
id=$(/usr/bin/docker --host unix:///run/ax6000-build/docker.sock info --format '{{.ID}}')
[ "$id" = "$1" ] || { echo 'Rootless engine identity mismatch' >&2; exit 91; }
sec=$(/usr/bin/docker --host unix:///run/ax6000-build/docker.sock info --format '{{join .SecurityOptions ","}}')
printf '%s\n' "$sec" | grep -Eq '(^|,)name=rootless(,|$)' || { echo 'Expected rootless security option' >&2; exit 92; }
shift
exec /usr/bin/docker --host unix:///run/ax6000-build/docker.sock "$@"
'''


def rootless_client(args, asset=None):
    command = ['run', '--rm', '--pull=never', '--network=none', '--read-only', '--user=2000:2000',
               '--cap-drop=ALL', '--security-opt=no-new-privileges', '--cpus=1', '--memory=2g', '--memory-swap=2g',
               '--pids-limit=128', '--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=16m', '--env=HOME=/tmp',
               '--label=' + LABEL_PREFIX + 'operator-import=true', '--entrypoint=/bin/sh',
               '--mount=type=bind,src=/usr/bin/docker,dst=/usr/bin/docker,readonly',
               '--mount=type=bind,src=' + ROOTLESS_SOCKET + ',dst=/run/ax6000-build/docker.sock']
    if asset is not None:
        asset = regular(asset).resolve()
        require(',' not in str(asset) and '\n' not in str(asset), 'Unsafe asset bind path')
        command.append('--mount=type=bind,src=' + str(asset) + ',dst=/assets/image.tar,readonly')
    command += [BASE_IMAGE, '-ec', CLIENT_GUARD, '--', ROOTLESS_ENGINE, *args]
    return docker(command, capture_output=True, text=True).stdout


def runtime_probe_command(image_id):
    return ['run', '--rm', '--pull=never', '--network=none', '--user=1000:1000', '--cap-drop=ALL',
            '--security-opt=no-new-privileges', '--cpus=1', '--memory=2g', '--memory-swap=2g', '--pids-limit=128',
            '--entrypoint=/bin/sh', image_id, '-ec',
            'test "$(id -u)" = 1000; test -w /builder; command -v flock; command -v timeout; '
            'flock --version; timeout --version; command -v make; command -v bash; command -v python3; test -f /builder/Makefile; '
            'sha256sum /builder/ax6000-imagebuilder.json']


def build_load(tree, proof, proof_sha, work):
    work = Path(work)
    require(not work.exists(), 'Build output directory must not already exist')
    base = inspect_image(BASE_TAG)
    require(base['Id'] == BASE_IMAGE and not base['Config'].get('OnBuild'), 'Approved local base tag changed or has build hooks')
    production_id = docker(['info', '--format', '{{.ID}}'], capture_output=True, text=True).stdout.strip()
    require(production_id != ROOTLESS_ENGINE, 'Production engine unexpectedly equals dedicated engine')
    before = docker(['ps', '--quiet', '--no-trunc'], capture_output=True, text=True).stdout.splitlines()
    # Validate rootless identity before constructing an image or exporting its bytes.
    rootless_client(['info', '--format', '{{.ID}}'])
    work.mkdir(mode=0o700, parents=True)
    context = work / 'context'
    context.mkdir()
    shutil.copytree(tree, context / 'builder', symlinks=True)
    dockerfile = context / 'Dockerfile'
    dockerfile.write_text(recipe(proof, proof_sha))
    tag = 'ax6000-asu-ib:' + proof['cohort'] + '-' + proof['archive_sha256'][:24]
    docker(['build', '--pull=false', '--network=none', '--no-cache', '--file', str(dockerfile),
            '--iidfile', str(work / 'image-id'), '--tag', tag, str(context)])
    image_id = (work / 'image-id').read_text().strip()
    image = inspect_image(image_id)
    require(inspect_image(BASE_TAG)['Id'] == BASE_IMAGE, 'Base tag moved during construction')
    validate_image(base, image, labels(proof, proof_sha))
    # Bounded, no-network probe executes only trusted base tools, not IB makefiles.
    probe = docker(runtime_probe_command(image_id), capture_output=True, text=True).stdout
    require(proof['attestation_sha256'] in probe, 'Built image attestation differs')
    image_tar = work / 'image.tar'
    docker(['image', 'save', '--output', str(image_tar), image_id])
    regular(image_tar)
    image_tar.chmod(0o444)  # Exact file bind bypasses the mode-0700 staging directory.
    rootless_client(['image', 'load', '--input', '/assets/image.tar'], image_tar)
    loaded = json.loads(rootless_client(['image', 'inspect', image_id]))[0]
    validate_image(base, loaded, labels(proof, proof_sha))
    require(loaded['Id'] == image_id, 'Rootless loaded image ID differs')
    rootless_probe = rootless_client(runtime_probe_command(image_id))
    require(proof['attestation_sha256'] in rootless_probe, 'Loaded image attestation differs')
    after = docker(['ps', '--quiet', '--no-trunc'], capture_output=True, text=True).stdout.splitlines()
    require(sorted(before) == sorted(after), 'Production running-container set changed; inspect before promotion')
    receipt = {'schema_version': 1, 'kind': 'ax6000-imagebuilder-image-load',
               'image_id': image_id, 'base_image_id': BASE_IMAGE, 'base_layers': base['RootFS']['Layers'],
               'image_layers': loaded['RootFS']['Layers'], 'archive_sha256': proof['archive_sha256'],
               'approval_receipt_sha256': proof_sha, 'attestation_sha256': proof['attestation_sha256'],
               'cohort': proof['cohort'], 'build_id': proof['build_id'], 'source_commit': proof['source_commit'],
               'loaded_engine_id': ROOTLESS_ENGINE, 'loaded_socket': ROOTLESS_SOCKET,
               'image_tar_sha256': sha256(image_tar), 'labels': labels(proof, proof_sha),
               'uid': 1000, 'gid': 1000, 'flock_timeout_available': True,
               'private_key_check': 'pinned independent approval plus archive names/markers scan',
               'native_make_executed': False, 'catalog_promoted': False}
    (work / 'load-receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--archive-sha256', required=True)
    parser.add_argument('--verification-receipt', type=Path, required=True)
    parser.add_argument('--verification-receipt-sha256', required=True)
    parser.add_argument('--profile', type=Path, required=True)
    parser.add_argument('--public-key', type=Path, required=True)
    parser.add_argument('--build-load', action='store_true', help='Explicitly build/export/load into the approved rootless engine')
    parser.add_argument('--output', type=Path, help='Fresh output directory, required only with --build-load')
    args = parser.parse_args(argv)
    require(not args.build_load or args.output is not None, '--build-load requires a fresh --output directory')
    proof = validate_inputs(args.archive, args.archive_sha256, args.verification_receipt,
                            args.verification_receipt_sha256, args.profile, args.public_key)
    with tempfile.TemporaryDirectory(prefix='asu-builder-validate-') as tmp:
        tree = unpack(args.archive, Path(tmp) / 'unpacked')
        scan = scan_tree(tree, proof)
        if args.build_load:
            result = build_load(tree, proof, args.verification_receipt_sha256, args.output)
        else:
            result = {'validated': True, 'image_built': False, 'image_loaded': False, 'scan': scan,
                      'base_image_id': BASE_IMAGE, 'rootless_engine_id': ROOTLESS_ENGINE,
                      'cohort': proof['cohort'], 'build_id': proof['build_id'],
                      'archive_sha256': args.archive_sha256,
                      'dockerfile': recipe(proof, args.verification_receipt_sha256)}
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit('ImageBuilder preparation refused: ' + str(error)) from error
