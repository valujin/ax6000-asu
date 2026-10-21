"""Actual ASGI submit/poll contracts, with a fake queue and no image execution."""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from test_policy import fixture


class HTTPContractTests(unittest.TestCase):
    def test_revision_overview_queue_and_cross_cohort_guards(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "catalog.json"
            catalog = fixture()
            catalog["firmware"]["version_code"] = "r0+33648-ec9ef10efc"
            data = json.dumps(catalog).encode()
            p.write_bytes(data)
            env = {
                **os.environ,
                "ASU_AX6000_CATALOG": str(p),
                "ASU_AX6000_CATALOG_SHA256": hashlib.sha256(data).hexdigest(),
                "ASU_AX6000_COHORT": "612-recommended",
                "PUBLIC_PATH": str(Path(tmp) / "public"),
            }
            code = r"""
from fastapi.testclient import TestClient
from asu.main import app
from asu.ax6000_policy import get_catalog
import asu.routers.api as api
class Job:
    id='a'*64
    kwargs={'cohort':'612-recommended','catalog_sha256':get_catalog().sha256}
    meta={}
    is_failed=False
    is_queued=True
    is_started=False
    is_finished=False
    enqueued_at='2026-10-21T00:00:00Z'
    def get_meta(self):return {}
    def get_position(self):return 0
    def return_value(self):return {"bin_dir":self.id,"images":[{"name":"missing.bin","size":1,"sha256":"a"*64}]}
    def delete(self):
        assert q.locked, 'Cache invalidation must share admission lock'
        q.job=None
class Queue:
    def __init__(self):self.job=None;self.enqueued=None;self.connection=self;self.locked=False
    def lock(self,*args,**kwargs):return self
    def __enter__(self):assert not self.locked;self.locked=True
    def __exit__(self,*args):self.locked=False
    def fetch_job(self,key):
        assert self.locked, 'Read job afresh under admission lock'
        return self.job
    length=0
    def __len__(self):return self.length
    def enqueue(self,*args,**kwargs):
        assert self.locked, 'Enqueue must share invalidation lock'
        self.enqueued=(args,kwargs);j=Job();j.id=kwargs['job_id'];j.kwargs=kwargs['kwargs'];self.job=j;return j
q=Queue();api.get_queue=lambda:q
with TestClient(app) as c:
    overview=c.get('/api/v1/overview',follow_redirects=True).json()
    assert isinstance(overview['branches'],dict)
    assert overview['branches']['25.12']['package_changes']==[]
    target=c.get('/api/v1/revision/25.12-SNAPSHOT/mediatek/filogic').json()['ax6000']
    assert target==overview['ax6000']
    index=c.get('/json/v1/releases/25.12-SNAPSHOT/targets/mediatek/filogic/index.json')
    assert index.status_code==200 and 'kernel' in index.json()['packages']
    assert c.get('/json/v1/releases/24.10/targets/mediatek/filogic/index.json').status_code==404
    assert c.get('/api/v1/revision/24.10-SNAPSHOT/mediatek/filogic').status_code==400
    request={'version':'25.12-SNAPSHOT','version_code':'r0+33648-ec9ef10efc','target':'mediatek/filogic',
        'profile':'xiaomi_redmi-router-ax6000-stock','packages':['busybox'],
        'installed_packages':['busybox'],'installed_package_manager':'apk','ax6000':target,'diff_packages':False}
    wrong={**request,'ax6000':{**target,'cohort':'612-latest'}}
    rejected=c.post('/api/v1/build',json=wrong)
    assert rejected.status_code==400,rejected.text
    assert q.job is None and q.enqueued is None
    result=c.post('/api/v1/build',json=request)
    assert result.status_code==202,result.text
    assert q.enqueued[0]==('asu.jobs.run',)
    assert q.enqueued[1]['kwargs']['cohort']=='612-recommended'
    normalized=q.enqueued[1]['kwargs']['request']
    assert 'kmod-mt_wifi' in normalized['packages'] and 'tailscale' not in normalized['packages']
    assert normalized['diff_packages'] is True
    job_id=q.job.id
    assert c.get('/api/v1/build/'+job_id).status_code==202
    q.job.is_queued=False;q.job.is_finished=True
    assert c.get('/api/v1/build/'+job_id).status_code==404
    assert q.job is None
    assert c.post('/api/v1/build',json=request).status_code==202
    q.job.is_queued=False;q.job.is_finished=True
    assert c.post('/api/v1/build',json=request).status_code==202
    q.job.kwargs={**q.job.kwargs,'cohort':'612-latest'}
    assert c.get('/api/v1/build/'+job_id).status_code==404
    wrong={**request,'ax6000':{**target,'cohort':'612-latest'}}
    assert c.post('/api/v1/build',json=wrong).status_code==400
    legacy={**request};legacy.pop('installed_package_manager')
    assert c.post('/api/v1/build',json=legacy).status_code==400
    assert c.post('/api/v1/build',content=b'x'*(256*1024+1)).status_code==413
    tail={**request,'packages':['busybox','tailscale']}
    assert c.post('/api/v1/build',json=tail).status_code==400
    q.job=None
    tail['installed_packages']=['busybox','tailscale']
    assert c.post('/api/v1/build',json=tail).status_code==202
    q.job=None;q.length=4
    assert c.post('/api/v1/build',json=tail).status_code==529
print('actual ASGI contract PASS; image execution deliberately not performed')
"""
            result = subprocess.run(
                [sys.executable, "-c", code],
                env=env,
                text=True,
                capture_output=True,
                timeout=45,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
