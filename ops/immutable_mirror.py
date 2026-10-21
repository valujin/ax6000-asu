"""Engine-free immutable APK3 mirror. Only an operator-pinned registry selects URLs.

Metadata is decoded by a hash-pinned host apk-tools, never target executables.
There is deliberately no Docker SDK, signing key, ASU import or external parser.
"""
from __future__ import annotations

import argparse
from contextlib import asynccontextmanager
import fcntl
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import selectors
import subprocess
import tempfile
import threading
import time
from urllib.parse import quote, urlsplit

MIB = 1024**2
MAX_FILE = 256 * MIB
MAX_CACHE = 2 * 1024**3
SHA = re.compile(r'[a-f0-9]{64}')
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.+-]{0,191}')
VERSION = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.+~:-]{0,191}')
FEEDS = {'base', 'luci', 'packages', 'routing', 'telephony', 'video'}
LOG = logging.getLogger(__name__)


class MirrorError(ValueError):
    """Reject activation or an unverified upstream response."""


def require(condition, message):
    if not condition:
        raise MirrorError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def file_sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def unique_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Duplicate JSON field')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def regular(path, cap):
    path = Path(path)
    require(path.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents)),
            'Absolute regular paths without symlink components are required')
    require(path.is_file() and 0 < path.stat().st_size <= cap, 'Missing or oversized trusted file')
    return path


def checked_bytes(path, expected, cap):
    require(isinstance(expected, str) and SHA.fullmatch(expected), 'Invalid SHA256 pin')
    data = regular(path, cap).read_bytes()
    require(sha256(data) == expected, 'Trusted file SHA256 differs')
    return data


class Decoder:
    """Bounded calls to the independently provisioned host APK3 binary."""
    def __init__(self, apk, expected):
        self.apk = regular(apk, 64 * MIB)
        require(os.access(self.apk, os.X_OK), 'Host APK is not executable')
        require(SHA.fullmatch(expected or '') and file_sha256(self.apk) == expected,
                'Trusted host APK SHA256 differs')

    def run(self, *args, cap=64 * MIB):
        process = subprocess.Popen([str(self.apk), '--no-network', *map(str, args)],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, close_fds=True)
        output, errors = bytearray(), bytearray()
        deadline = time.monotonic() + 45
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, output)
                selector.register(process.stderr, selectors.EVENT_READ, errors)
                while selector.get_map():
                    require(time.monotonic() < deadline, 'Host APK command timed out')
                    for key, _ in selector.select(timeout=0.2):
                        block = os.read(key.fileobj.fileno(), 16384)
                        if not block:
                            selector.unregister(key.fileobj)
                            continue
                        key.data.extend(block)
                        require(len(output) <= cap and len(errors) <= 65536, 'Host APK output cap exceeded')
            require(process.wait(timeout=5) == 0, 'Host APK rejected data')
            return bytes(output)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stdout.close()
            process.stderr.close()

    def index(self, path):
        obj = unique_json(self.run('adbdump', '--format', 'json', path))
        require(isinstance(obj, dict) and isinstance(obj.get('packages'), list), 'Invalid APK3 index object')
        require(obj.get('pkgname-spec', '${name}-${version}.apk') == '${name}-${version}.apk',
                'Custom upstream package paths are not accepted')
        require(0 < len(obj['packages']) <= 50000, 'Invalid index package count')
        rows = {}
        for item in obj['packages']:
            require(isinstance(item, dict), 'Invalid package record')
            name, version = item.get('name'), item.get('version')
            require(isinstance(name, str) and NAME.fullmatch(name), 'Invalid indexed name')
            require(isinstance(version, str) and VERSION.fullmatch(version), 'Invalid indexed version')
            require(item.get('arch') in {'aarch64_cortex-a53', 'noarch'}, 'Foreign package architecture')
            require(isinstance(item.get('hashes'), str) and SHA.fullmatch(item['hashes']),
                    'Only native SHA256 index identities are accepted')
            require(type(item.get('file-size')) is int and 0 < item['file-size'] <= 2**40,
                    'Missing indexed APK length')
            filename = name + '-' + version + '.apk'
            require(filename not in rows, 'Duplicate indexed filename')
            rows[filename] = item
        return rows

    def verify_index(self, index, key_bytes):
        with tempfile.TemporaryDirectory(prefix='apk-official-key-') as tmp:
            key = Path(tmp) / 'official.pem'
            key.write_bytes(key_bytes)
            self.run('--keys-dir', tmp, 'verify', index, cap=MIB)

    def verify_package(self, package, expected):
        # Official APKs can be unsigned: this verifies payload integrity, then
        # mkndx recomputes the native identity bound by the signed official row.
        self.run('--allow-untrusted', 'verify', package, cap=MIB)
        with tempfile.TemporaryDirectory(prefix='apk-native-identity-') as tmp:
            rebuilt = Path(tmp) / 'packages.adb'
            self.run('mkndx', '--allow-untrusted', '--hash', 'sha256', '--output', rebuilt, package, cap=MIB)
            rows = self.index(rebuilt)
            require(len(rows) == 1 and next(iter(rows.values())) == expected,
                    'APK native identity or metadata differs from signed index')


def origin_base(record):
    distribution, feed, base = record.get('distribution'), record.get('feed'), record.get('base_url')
    require(distribution in {'immortalwrt', 'openwrt'} and feed in FEEDS and isinstance(base, str),
            'Invalid distribution/feed origin')
    url = urlsplit(base)
    require(url.scheme == 'https' and url.netloc == 'downloads.' + distribution + '.org'
            and not url.query and not url.fragment and not url.username and not url.password,
            'Only the approved HTTPS distribution origin is accepted')
    require(re.fullmatch(r'/releases/(?:25\.12(?:\.\d+|-SNAPSHOT)?/packages|packages-25\.12)'
                         r'/aarch64_cortex-a53/' + feed + '/', url.path),
            'Only 25.12 aarch64 public userspace repository paths are accepted')
    return base


class Repository:
    def __init__(self, record, decoder):
        require(isinstance(record, dict), 'Invalid repository definition')
        self.base = origin_base(record)
        self.feed, self.sha = record['feed'], record.get('index_sha256')
        self.data = checked_bytes(record.get('index_path', ''), self.sha, 16 * MIB)
        key = checked_bytes(record.get('key_path', ''), record.get('key_sha256'), 16384)
        require(key.startswith(b'-----BEGIN PUBLIC KEY-----\n') and b'PRIVATE' not in key,
                'An official public PEM key is required')
        # Verify the exact bytes retained in memory, avoiding a mutable source
        # file changing between checksum, signature verification and decoding.
        with tempfile.TemporaryDirectory(prefix='apk-frozen-index-') as tmp:
            index = Path(tmp) / 'packages.adb'
            index.write_bytes(self.data)
            decoder.verify_index(index, key)
            self.rows = decoder.index(index)


class Cache:
    def __init__(self, directory, decoder, client, limit, max_file):
        self.root = Path(directory)
        require(self.root.is_absolute() and not any(p.is_symlink() for p in (self.root, *self.root.parents)),
                'Cache directory must be an absolute dedicated directory without symlinks')
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.owner = os.open(self.root / '.mirror.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self.owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(self.owner)
            raise MirrorError('Use exactly one mirror process per dedicated cache')
        self.payload = self.root / 'payload'
        require(not self.payload.is_symlink(), 'Unsafe payload cache')
        self.payload.mkdir(mode=0o700, exist_ok=True)
        self.decoder, self.client, self.limit, self.max_file = decoder, client, limit, max_file
        self.lock = threading.RLock()
        self.fetch_slots = threading.BoundedSemaphore(2)
        self.entries = {}
        self.reserved = 0
        # Recovered files are not trusted until revalidated against signed rows.
        for directory in self.payload.iterdir():
            require(directory.is_dir() and not directory.is_symlink() and SHA.fullmatch(directory.name),
                    'Unexpected cache directory')
            for path in directory.iterdir():
                require(path.is_file() and not path.is_symlink(), 'Unsafe payload cache entry')
                if path.name.startswith('.download-'):
                    path.unlink()
                else:
                    require(path.name.endswith('.apk'), 'Unexpected cached file')
                    self.entries[(directory.name, path.name)] = {
                        'path': path, 'size': path.stat().st_size, 'hash': None,
                        'time': path.stat().st_mtime, 'leases': 0, 'busy': False}
        with self.lock:
            self.evict(0)

    def evict(self, needed):
        while sum(x['size'] for x in self.entries.values()) + self.reserved + needed > self.limit:
            victims = [(key, item) for key, item in self.entries.items() if not item['leases'] and not item['busy']]
            require(victims, 'Verified cache capacity is in use')
            key, item = min(victims, key=lambda x: x[1]['time'])
            item['path'].unlink(missing_ok=True)
            del self.entries[key]

    def open(self, repo, filename):
        expected = repo.rows[filename]
        require(expected['file-size'] <= self.max_file and expected['file-size'] <= self.limit,
                'Indexed APK exceeds the configured file/cache cap')
        key = (repo.sha, filename)
        # The two slots bound download, verification and disk reservations.
        # A lock per cache avoids duplicate fetches without unbounded lock maps.
        with self.fetch_slots:
            with self.lock:
                existing = self.entries.get(key)
                if existing is not None:
                    path = existing['path']
                    require(not path.is_symlink() and path.is_file(), 'Unsafe cached payload')
                    existing['busy'] = True
                    try:
                        require(path.stat().st_size == expected['file-size'], 'Cached APK length differs')
                        digest = file_sha256(path)
                        if existing['hash'] is None:
                            self.decoder.verify_package(path, expected)
                            existing['hash'] = digest
                        require(digest == existing['hash'], 'Cached payload was changed')
                    except (ValueError, OSError):
                        path.unlink(missing_ok=True)
                        del self.entries[key]
                        existing = None
                    else:
                        existing['busy'] = False
                        return self.lease(key, existing)
                amount = expected['file-size']
                self.evict(amount)
                destination = self.payload / repo.sha
                destination.mkdir(mode=0o700, exist_ok=True)
                require(not destination.is_symlink(), 'Unsafe cache generation directory')
                fd, temporary = tempfile.mkstemp(prefix='.download-', dir=destination)
                self.reserved += amount
            try:
                with os.fdopen(fd, 'wb') as output:
                    url = repo.base + quote(filename, safe='-._~+')
                    with self.client.stream('GET', url, headers={'accept-encoding': 'identity'}) as response:
                        require(response.status_code == 200, 'Origin returned an error or redirect')
                        require(response.headers.get('content-encoding', 'identity') == 'identity',
                                'Encoded APK responses are not accepted')
                        if 'content-length' in response.headers:
                            require(response.headers['content-length'].isdecimal()
                                    and int(response.headers['content-length']) == amount,
                                    'Origin content length differs from signed index')
                        length = 0
                        deadline = time.monotonic() + 90
                        for chunk in response.iter_raw():
                            length += len(chunk)
                            require(time.monotonic() < deadline and length <= amount and length <= self.max_file,
                                    'APK stream exceeded its time/size bound')
                            output.write(chunk)
                        require(length == amount, 'Truncated APK response')
                    output.flush()
                    os.fsync(output.fileno())
                path = Path(temporary)
                self.decoder.verify_package(path, expected)
                digest = file_sha256(path)
                with self.lock:
                    target = destination / filename
                    os.replace(path, target)
                    # Another request for this same object may already have
                    # completed. Its open descriptor remains valid if replaced.
                    previous = self.entries.get(key)
                    item = {'path': target, 'size': amount, 'hash': digest, 'time': time.time(),
                            'leases': previous['leases'] if previous else 0, 'busy': False}
                    self.entries[key] = item
                    self.reserved -= amount
                    amount = 0
                    return self.lease(key, item)
            finally:
                Path(temporary).unlink(missing_ok=True)
                with self.lock:
                    self.reserved -= amount

    def lease(self, key, item):
        # Called under the cache lock. Open before LRU can remove this pathname.
        stream = item['path'].open('rb')
        item['time'] = time.time()
        item['leases'] += 1
        released = False
        def release():
            nonlocal released
            with self.lock:
                if not released:
                    stream.close()
                    current = self.entries.get(key)
                    if current:
                        current['leases'] -= 1
                    released = True
        def chunks():
            try:
                while block := stream.read(65536):
                    yield block
            finally:
                release()
        return chunks(), item['hash'], item['size'], release

    def close(self):
        os.close(self.owner)


def create_app(registry_path, registry_sha256, apk_path, apk_sha256, cache_dir, *,
               transport=None, max_file_bytes=MAX_FILE, cache_bytes=MAX_CACHE):
    """Activate only the operator's hash-pinned registry; no client-selected URLs."""
    # Decoding/verification helpers remain stdlib-only for the offline promoter.
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import Response, StreamingResponse
    import httpx
    require(type(max_file_bytes) is int and 0 < max_file_bytes <= MAX_FILE,
            'File cap may only be reduced')
    require(type(cache_bytes) is int and 0 < cache_bytes <= MAX_CACHE, 'Cache cap may only be reduced')
    decoder = Decoder(apk_path, apk_sha256)
    data = unique_json(checked_bytes(registry_path, registry_sha256, 8 * MIB))
    require(isinstance(data, dict) and data.get('schema_version') == 1
            and isinstance(data.get('snapshots'), list) and 0 < len(data['snapshots']) <= 1024,
            'Invalid operator registry')
    repositories = {}
    for snapshot in data['snapshots']:
        require(isinstance(snapshot, dict) and SHA.fullmatch(snapshot.get('snapshot_sha256', '')),
                'Invalid restored signed snapshot SHA256')
        require(isinstance(snapshot.get('repositories'), list) and 0 < len(snapshot['repositories']) <= 24,
                'Invalid snapshot repository list')
        for record in snapshot['repositories']:
            repo = Repository(record, decoder)
            key = (snapshot['snapshot_sha256'], repo.sha, repo.feed)
            require(key not in repositories, 'Duplicate immutable repository identity')
            repositories[key] = repo
    client = httpx.Client(timeout=httpx.Timeout(30, connect=10), follow_redirects=False,
                          trust_env=False, transport=transport,
                          limits=httpx.Limits(max_connections=2, max_keepalive_connections=2))
    cache = Cache(cache_dir, decoder, client, cache_bytes, max_file_bytes)

    @asynccontextmanager
    async def lifespan(app):
        try:
            yield
        finally:
            client.close()
            cache.close()

    app = FastAPI(title='Immutable APK mirror', docs_url=None, redoc_url=None,
                  openapi_url=None, lifespan=lifespan)
    app.state.repositories = repositories
    app.state.mirror_cache = cache
    app.state.mirror_client = client

    class LeasedResponse(StreamingResponse):
        async def __call__(self, scope, receive, send):
            try:
                await super().__call__(scope, receive, send)
            finally:
                self.release()

    @app.get('/immutable/{snapshot}/public/{index}/{feed}/{filename}')
    def serve(snapshot: str, index: str, feed: str, filename: str):
        repo = repositories.get((snapshot, index, feed))
        if repo is None or (filename != 'packages.adb' and filename not in repo.rows):
            raise HTTPException(404, 'Unknown immutable object')
        headers = {'cache-control': 'public, max-age=31536000, immutable', 'x-content-type-options': 'nosniff'}
        if filename == 'packages.adb':
            headers['etag'] = '"' + repo.sha + '"'
            return Response(repo.data, media_type='application/octet-stream', headers=headers)
        try:
            chunks, digest, size, release = cache.open(repo, filename)
        except (ValueError, OSError, subprocess.SubprocessError, httpx.HTTPError, httpx.StreamError) as error:
            LOG.warning('Indexed APK rejected: %s', type(error).__name__)
            raise HTTPException(502, 'Indexed APK unavailable or failed verification') from error
        headers.update({'etag': '"' + digest + '"', 'content-length': str(size)})
        response = LeasedResponse(chunks, media_type='application/octet-stream', headers=headers)
        response.release = release
        return response

    return app


def create_from_env():
    """Uvicorn --factory entry point. Production limits cannot be raised by env."""
    return create_app(os.environ['AX6000_MIRROR_REGISTRY'], os.environ['AX6000_MIRROR_REGISTRY_SHA256'],
                      os.environ['AX6000_MIRROR_APK'], os.environ['AX6000_MIRROR_APK_SHA256'],
                      os.environ['AX6000_MIRROR_CACHE'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['check'])
    for name in ['registry', 'registry-sha256', 'apk', 'apk-sha256', 'cache']:
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    app = create_app(args.registry, args.registry_sha256, args.apk, args.apk_sha256, args.cache)
    print(json.dumps({'schema_version': 1, 'registry_sha256': args.registry_sha256,
                      'repositories': [{'snapshot_sha256': snapshot, 'index_sha256': index, 'feed': feed}
                                       for snapshot, index, feed in sorted(app.state.repositories)]}, sort_keys=True))
    app.state.mirror_client.close()
    app.state.mirror_cache.close()


if __name__ == '__main__':
    main()
