"""Tiny real-file lock fixture; no actual Docker, source, archives or firmware."""
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

class SmokeLifetimeTests(unittest.TestCase):
    smoke_path=Path(__file__).parents[1]/'smoke_imagebuilder.py'
    def test_real_host_lease_covers_export_unpack_inspect_and_busy_handoff_refuses(self):
        import fcntl
        spec=importlib.util.spec_from_file_location('lease_fixture_smoke',self.smoke_path)
        smoke=importlib.util.module_from_spec(spec);spec.loader.exec_module(smoke)
        info='''Current Target: "mediatek/filogic"
Default Packages: busybox opkg kernel kmod-mt_wifi
Available Profiles:
xiaomi_redmi-router-ax6000-stock:
    Packages:\x20
    SupportedDevices: xiaomi,redmi-router-ax6000-stock
'''
        for busy in (False,True):
            with self.subTest(busy=busy),tempfile.TemporaryDirectory() as t:
                root=Path(t);lock=root/'tiny-fixture-lock';lock.touch();events=[];state={'stopped':False};cid='c'*64
                competitor=lock.open('rb')
                def assert_held():
                    with lock.open('rb') as probe:
                        with self.assertRaises(BlockingIOError):fcntl.flock(probe,fcntl.LOCK_EX|fcntl.LOCK_NB)
                def client(args,verifier,**kwargs):
                    if args[:2]==['container','create']:return cid.encode()
                    if args[:2]==['container','stop']:
                        state['stopped']=True;events.append('stop')
                        if busy:fcntl.flock(competitor,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    if args[:2]==['container','inspect']:return json.dumps([{'Id':cid,'State':{'Running':not state['stopped']}}]).encode()
                    if args[:2]==['container','rm']:events.append('remove')
                    if 'make' in args:
                        events.append(next(x for x in ('info','manifest','image') if x in args))
                    if args[:2]==['container','cp'] and args[-1]=='-':assert_held();events.append('export')
                    if kwargs.get('destination'):kwargs['destination'].write_text(info if 'info' in args else 'fixture')
                    return b''
                def unpack(*args):assert_held();events.append('unpack')
                def inspect(*args):assert_held();events.append('inspect');return {'fixture_only':True}
                defaults={'busybox':'1','opkg':'1','kernel':'fixture-ABI','kmod-mt_wifi':'1'}
                context={'overlay':{},'defaults':{'stock':defaults},'controls':{k:{'Version':v} for k,v in defaults.items()},'profile':{'firmware':{'kernel_version':'fixture-ABI'}},'verifier':SimpleNamespace(device_manifest=lambda _:defaults)}
                try:
                    with patch.object(smoke,'LOCK',str(lock)),patch.object(smoke,'client',side_effect=client),patch.object(smoke,'assert_container'),patch.object(smoke,'wait_lock'),patch.object(smoke,'validate_caps'),patch.object(smoke,'unpack_outputs',side_effect=unpack),patch.object(smoke,'inspect_artifacts',side_effect=inspect):
                        if busy:
                            with self.assertRaises(BlockingIOError):smoke.run_layout('stock',root,SimpleNamespace(image_id='sha256:'+'a'*64),context,lock.stat())
                            self.assertEqual(events,['info','manifest','image','stop','remove'])
                        else:
                            smoke.run_layout('stock',root,SimpleNamespace(image_id='sha256:'+'a'*64),context,lock.stat())
                            self.assertEqual(events,['info','manifest','image','stop','export','unpack','inspect','remove'])
                finally:competitor.close()


if __name__=='__main__':unittest.main()
