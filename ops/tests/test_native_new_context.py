"""Synthetic schema3 custody; no actual native source/archive/acceptance execution."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result
acceptance=module('schema3_acceptance',ROOT/'ops/native_acceptance.py')

def ref(path):
    with path.open('rb') as stream:pin=hashlib.file_digest(stream,'sha256').hexdigest()
    return {'path':str(path),'sha256':pin,'size':path.stat().st_size}

def emit(path,value):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value));return ref(path)

class NewContextContracts(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.helper=module('synthetic_new_native',ROOT/'ops/native_new_context.py')
        self.source,self.original,self.raw=(self.root/name for name in ('owned','original','raw'))
        candidate={'kind':'rec-native-candidate-context-p5-v1','schema_version':1,'native_acceptance':None,'independently_verified':False,'prior_image_equal':False,'prior_abi_context_equal':True,'sdk_context_expected':{}}
        for name,directory in (('owned_context',self.source),('original_context',self.original)):
            rows={};candidate[name]={'required_files':rows}
            for role in self.helper.SEVEN:
                relative=self.helper.KROOT+'/'+role;p=directory/relative;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(('synthetic '+role).encode())
                value={k:ref(p)[k] for k in ('sha256','size')};candidate['sdk_context_expected'][role]=value
                if role in self.helper.ROLES:rows[role]={'path':relative,**value}
            # Sparse, non-executable zero fixtures match the fixed logical size;
            # no real kernel bytes are present and physical storage stays tiny.
            image=directory/'Image'
            with image.open('wb') as stream:
                stream.write(name.encode());stream.truncate(14661640)
            rows['KDIR/Image']={'path':'Image',**{k:ref(image)[k] for k in ('sha256','size')}}
        self.helper.NEW=candidate['owned_context']['required_files']['KDIR/Image']['sha256']
        self.helper.OLD=candidate['original_context']['required_files']['KDIR/Image']['sha256']
        self.candidate=candidate;owned,prior=self.helper.contexts(candidate)
        self.candidate_path=self.root/'candidate.json';candidate_ref=emit(self.candidate_path,candidate);self.helper.CANDIDATE_SHA=candidate_ref['sha256']
        self.world_path=self.root/'world.json';world_ref=emit(self.world_path,{'producer_completed':False,'producer_exit_code':1,'native_acceptance':None,'world_command_exit_zero_inferred':True,'raw_process_wait_status':None});self.helper.WORLD_SHA=world_ref['sha256']
        self.profile={'id':'redmi-ax6000-612-recommended','build_id':'SYNTHETIC-NOT-ACCEPTED','channel':'recommended','package_manager':'apk','asu':{'cohort':'612-recommended','seed':self.helper.SEED},'firmware':{'commit':self.helper.SOURCE,'kernel_version':self.helper.ABI,'architecture':'aarch64_cortex-a53'},'sdk':{'sha256':'a'*64,'url':'https://fixture.invalid/sdk'}}
        manifest={'recipe_commit':self.helper.PRODUCER,'source_commit':self.helper.SOURCE,'build_id':self.profile['build_id'],'kernel_version':self.helper.ABI}
        rows={name:emit(self.raw/name,value) for name,value in [('profile.json',self.profile),('lock.json',{'synthetic':True}),('firmware-manifest.json',manifest)]}
        (self.raw/'build.config').write_bytes(b'CONFIG_USE_APK=y\n');(self.source/'.config').write_bytes(b'CONFIG_USE_APK=y\n');rows['build.config']=ref(self.raw/'build.config')
        image=owned['KDIR/Image'];self.native={'schema_version':1,'ok':True,'build_id':self.profile['build_id'],'source_commit':self.helper.SOURCE,'kernel_abi':self.helper.ABI,'package_manager':'apk','channel':'recommended','sysupgrade_input':image,'layouts':{name:{'kernel':image} for name in ('stock','mtkuboot','ubootmod')},'sdk_context':{'sdk_sha256':'a'*64,'matching_contexts':candidate['sdk_context_expected']}}
        self.native_path=self.root/'native.json';native_ref=emit(self.native_path,self.native)
        inspect=emit(self.root/'terminal.json',{'Id':'f'*64,'State':{'Status':'exited','Running':False,'ExitCode':0,'OOMKilled':False}})
        phases={}
        for name in ('before-packaging','after-imagebuilder','after-export'):
            phases[name]=emit(self.root/(name+'.json'),{'phase':name,'candidate_context':True,'native_acceptance':None,'prior_owned_Image_byte_identity':False,'original_source_readonly_guards_passed':True,'native_context':owned,'original_native_context':prior,'source_context7':candidate['sdk_context_expected']})
        completion={'schema_version':1,'kind':'rec-native-packaging-completion-v1','completed':True,'native_evidence':None,'producer_commit':self.helper.PRODUCER,'source_commit':self.helper.SOURCE,'candidate_context':candidate_ref,'world_success_custody':world_ref,'stages':[{'steps':['imagebuilder','export'],'inspect':inspect}],'phase_receipts':phases,'raw_metadata4':rows}
        completion_ref=emit(self.root/'completion.json',completion)
        baseline=emit(self.root/'baseline.json',{'schema_version':1,'source_commit':self.helper.SOURCE,'kernel_version':self.helper.ABI,'package_manager':'apk','architecture':'aarch64_cortex-a53'})
        bank=emit(self.root/'native-bank.json',{'synthetic_only':True})
        self.status={'schema_version':3,'kind':'ax6000-native-new-context-acceptance-v1','ok':True,'cohort':'612-recommended','channel':'recommended','package_manager':'apk','producer_commit':self.helper.PRODUCER,'source_commit':self.helper.SOURCE,'seed':self.helper.SEED,'kernel_abi':self.helper.ABI,'build_id':self.profile['build_id'],'all_layouts_verified':True,'container_exit_code':0,'oom_killed':False,'prior_image_equal':False,'prior_abi_context_equal':True,'strict_accepted_context_unchanged':False,'strict_new_context_unchanged':True,'original_source_readonly_guards_passed':True,'historical_archive_observations_replayed_as_live_pins':False,'full_native_verifier_unchanged':True,'accepted_kernel_image':image,'prior_kernel_image':prior['KDIR/Image'],'prior_context':prior,'strict_context_before':owned,'strict_context_after':owned,'original_source_context_before':prior,'original_source_context_after':prior,'source_context7':candidate['sdk_context_expected'],'candidate_context':candidate_ref,'world_success_custody':world_ref,'producer_completion':completion_ref,'native_evidence':native_ref,'evidence_sha256':native_ref['sha256'],'sdk_baseline':baseline,'native_bank_sha256':bank['sha256'],'source':str(self.source),'original_source':str(self.original),'raw':str(self.raw),'sdk':self.profile['sdk'],'native_input_records':{r['path']:{k:r[k] for k in ('sha256','size')} for r in rows.values()},'native_inputs':{n:{k:r[k] for k in ('sha256','size')} for n,r in rows.items() if n!='build.config'}}
        self.path=self.root/'status.json'

    def verify(self,**overrides):
        value=emit(self.path,self.status)
        kwargs={'cohort':'612-recommended','profile':self.profile,'native':self.native,'native_evidence':self.native_path,'native_evidence_sha256':self.status['evidence_sha256'],'raw':self.raw,'source':self.source,'recipe_commit':self.helper.PRODUCER}|overrides
        with patch.object(acceptance,'new_context_module',return_value=self.helper,create=True),patch.object(acceptance,'NEW_CONTEXT_STATUS_SHA',value['sha256'],create=True):
            return acceptance.verify(self.path,value['sha256'],**kwargs)

    def test_exact_typed_new_context_without_relabeling_old_image(self):
        result=self.verify();self.assertTrue(result['strict_new_context_unchanged']);self.assertFalse(result['strict_accepted_context_unchanged']);self.assertFalse(result['prior_image_equal']);self.assertTrue(result['prior_abi_context_equal'])
        self.assertEqual(result['accepted_kernel_image'],self.status['accepted_kernel_image'])

    def test_wrong_channel_producer_candidate_or_failed_status_rejected(self):
        for kwargs in ({'cohort':'66'},{'cohort':'612-latest'},{'recipe_commit':acceptance.PRODUCER}):
            with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):self.verify(**kwargs)
        original=copy.deepcopy(self.status)
        for name,value in [('kind','rec-native-candidate-context-p5-v1'),('ok',False),('strict_accepted_context_unchanged',True),('strict_new_context_unchanged',False),('prior_image_equal',True),('container_exit_code',1),('oom_killed',True),('full_native_verifier_unchanged',False)]:
            self.status=original|{name:value}
            with self.subTest(name=name),self.assertRaises(ValueError):self.verify()
        self.status=original

    def test_current_owned_and_original_image_and_all_seven_roles_exact(self):
        paths=[self.source/'.config',self.source/'Image',self.original/'Image',*(root/self.helper.KROOT/r for root in (self.source,self.original) for r in self.helper.SEVEN)]
        for p in paths:
            with p.open('r+b') as f:before=f.read(1);f.seek(0);f.write(b'!')
            with self.subTest(path=p),self.assertRaises(ValueError):self.verify()
            with p.open('r+b') as f:f.write(before)

    def test_wrong_native_layout_kernel_or_sdk_rejected(self):
        original=copy.deepcopy(self.native)
        for field in ('stock','mtkuboot','ubootmod'):
            self.native=copy.deepcopy(original);self.native['layouts'][field]['kernel']=self.status['prior_kernel_image'];self.status['native_evidence']=emit(self.native_path,self.native);self.status['evidence_sha256']=self.status['native_evidence']['sha256']
            with self.subTest(layout=field),self.assertRaises(ValueError):self.verify()
        self.native=copy.deepcopy(original);self.native['sdk_context']['matching_contexts']={};self.status['native_evidence']=emit(self.native_path,self.native);self.status['evidence_sha256']=self.status['native_evidence']['sha256']
        with self.assertRaises(ValueError):self.verify()

    def test_raw_bank_custody_or_world_failure_scope_cannot_be_rewritten(self):
        (self.raw/'build.config').write_bytes(b'changed')
        with self.assertRaises(ValueError):self.verify()
        (self.raw/'build.config').write_bytes(b'CONFIG_USE_APK=y\n')
        bank=self.root/'native-bank.json';bank.write_text('{}')
        with self.assertRaises(ValueError):self.verify()
        emit(bank,{'synthetic_only':True})
        world=json.loads(self.world_path.read_text());world['producer_completed']=True;row=emit(self.world_path,world);self.status['world_success_custody']=row;self.helper.WORLD_SHA=row['sha256']
        with self.assertRaises(ValueError):self.verify()

    def test_wrong_explicit_digest_or_source_namespace_rejected(self):
        emit(self.path,self.status)
        with self.assertRaises(ValueError):acceptance.verify(self.path,'0'*64,cohort='612-recommended',profile=self.profile,native=self.native,native_evidence=self.native_path,native_evidence_sha256=self.status['evidence_sha256'],raw=self.raw,source=self.source,recipe_commit=self.helper.PRODUCER)
        with self.assertRaises(ValueError):self.verify(source=self.original)

if __name__=='__main__':unittest.main()
