"""Finite REC schema3 acceptance consumer. Never accepts a candidate as status."""
import hashlib
import json
from pathlib import Path
import re

PRODUCER='b122c35046ab1c3cd03828aabd168bb35466e2c8'
SOURCE='ae65e1de69971b5a2e3cf7e39390ee93f274d488'
SEED='3254dd70ea96217f41221b29998780639bbf2e7f33deb735c8bd7b380274c4e3'
ABI='6.12.108~942ed17ba3e2c90bc1373619dd44dedc-r1'
OLD='5a0eedece2116a8dd046bd8337b487bdfc6913eaf1465d3dc6b711d0851ad611'
NEW='ac19e2c554e40219aed043a0760aef2a609743ec0437d295c4f7f15f51886d8f'
CANDIDATE_SHA='7198fc7893cb983354694167923236852fc40558d8ff327489461810a0e026f2'
WORLD_SHA='24df2dbb20d014de20ea8973a9aabbb4d29e6731162711fac310266f8364bd78'
ROLES={'.config','.vermagic','Module.symvers','include/config/kernel.release','KDIR/Image'}
SEVEN={'.config','.config.set','.vermagic','Module.symvers','include/config/kernel.release','include/generated/autoconf.h','modules.builtin.modinfo'}
KROOT='build_dir/target-aarch64_cortex-a53_musl/linux-mediatek_filogic/linux-6.12.108'


def need(value,message):
    if not value:raise ValueError(message)


def record(path):
    p=Path(path);need(p.is_file() and p.resolve()==p and not p.is_symlink(),'Expected canonical regular metadata/context')
    with p.open('rb') as f:return {'sha256':hashlib.file_digest(f,'sha256').hexdigest(),'size':p.stat().st_size}


def contexts(candidate):
    need(candidate.get('kind')=='rec-native-candidate-context-p5-v1' and candidate.get('schema_version')==1
         and candidate.get('native_acceptance','missing') is None and candidate.get('independently_verified') is False
         and candidate.get('prior_image_equal') is False and candidate.get('prior_abi_context_equal') is True,
         'P5 candidate must remain explicitly unaccepted')
    def view(name):
        rows=candidate[name]['required_files'];need(set(rows)==ROLES,'Complete five functional roles required')
        return {k:{t:v[t] for t in ('sha256','size')} for k,v in rows.items()}
    owned,prior=view('owned_context'),view('original_context')
    need(owned['KDIR/Image']=={'sha256':NEW,'size':14661640} and prior['KDIR/Image']=={'sha256':OLD,'size':14661640},'Exact complete old/new Image identities required')
    need(all(owned[r]==prior[r] for r in ROLES-{'KDIR/Image'}) and set(candidate['sdk_context_expected'])==SEVEN,'Exact ABI4/SDK7 required')
    return owned,prior


def validate_state(status,candidate):
    owned,prior=contexts(candidate)
    need(status.get('schema_version')==3 and status.get('kind')=='ax6000-native-new-context-acceptance-v1','Only independent schema3 native acceptance is accepted')
    for k,v in {'ok':True,'all_layouts_verified':True,'oom_killed':False,'prior_image_equal':False,
                'prior_abi_context_equal':True,'strict_accepted_context_unchanged':False,
                'strict_new_context_unchanged':True,'original_source_readonly_guards_passed':True,
                'historical_archive_observations_replayed_as_live_pins':False,'full_native_verifier_unchanged':True}.items():
        need(status.get(k) is v,'Wrong native status flag: '+k)
    need(type(status.get('container_exit_code')) is int and status['container_exit_code']==0,'Actual independent verifier exit0 required')
    for k,v in {'cohort':'612-recommended','channel':'recommended','package_manager':'apk','producer_commit':PRODUCER,'source_commit':SOURCE,'seed':SEED,'kernel_abi':ABI}.items():
        need(status.get(k)==v,'Wrong native identity: '+k)
    for k,v in {'prior_kernel_image':prior['KDIR/Image'],'accepted_kernel_image':owned['KDIR/Image'],
                'prior_context':prior,'strict_context_before':owned,'strict_context_after':owned,
                'original_source_context_before':prior,'original_source_context_after':prior,
                'source_context7':candidate['sdk_context_expected']}.items():
        need(status.get(k)==v,'Complete native context differs: '+k)


def packaging(value):
    need(value.get('schema_version')==1 and value.get('kind')=='rec-native-packaging-completion-v1'
         and value.get('completed') is True and value.get('native_evidence','missing') is None
         and value.get('producer_commit')==PRODUCER and value.get('source_commit')==SOURCE,
         'Genuine successful P5 packaging completion required')
    need(len(value.get('stages',[]))==1 and value['stages'][0].get('steps')==['imagebuilder','export']
         and set(value.get('phase_receipts',{}))=={'before-packaging','after-imagebuilder','after-export'},
         'P5 actual IB/export phases required; no inferred producer success')


def load_accepted(path,pin,resolve=lambda value:Path(value)):
    refs={}
    def checked(row,expected=None,json_body=True):
        need(isinstance(row,dict) and set(row)=={'path','sha256','size'} and Path(row['path']).is_absolute()
             and re.fullmatch('[0-9a-f]{64}',row['sha256'] or '') and type(row['size']) is int,'Malformed accepted fullref')
        p=resolve(row['path']);need(record(p)=={k:row[k] for k in ('sha256','size')}
             and (expected is None or row['sha256']==expected),'Accepted metadata bytes changed')
        need(p.stat().st_size<=8*1024**2,'Metadata exceeds bound')
        refs[row['path']]=row
        return json.loads(p.read_text()) if json_body else None
    actual=record(Path(path));need(actual['sha256']==pin and actual['size']<=8*1024**2,'Explicit bounded actual native status SHA required')
    refs[str(Path(path))]={'path':str(Path(path)),**actual}
    status=json.loads(Path(path).read_text())
    candidate=checked(status['candidate_context'],CANDIDATE_SHA);validate_state(status,candidate)
    world=checked(status['world_success_custody'],WORLD_SHA)
    need(world['producer_completed'] is False and world['producer_exit_code']==1 and world['native_acceptance'] is None
         and world['world_command_exit_zero_inferred'] is True and world['raw_process_wait_status'] is None,'P4 failed producer/world inference must remain separate')
    completion=checked(status['producer_completion']);packaging(completion)
    need(completion['candidate_context']==status['candidate_context'] and completion['world_success_custody']==status['world_success_custody'],'P5 context/world custody differs')
    observed=checked(completion['stages'][0]['inspect'])
    state=observed['State'];need(state['Status']=='exited' and state['Running'] is False and type(state['ExitCode']) is int and state['ExitCode']==0 and state['OOMKilled'] is False,'Actual P5 producer terminal0/noOOM required')
    owned,prior=contexts(candidate)
    for name,row in completion['phase_receipts'].items():
        phase=checked(row)
        need(phase.get('phase')==name and phase.get('candidate_context') is True and phase.get('native_acceptance','missing') is None
             and phase.get('prior_owned_Image_byte_identity') is False and phase.get('original_source_readonly_guards_passed') is True,'Typed P5 phase guard required')
        for key,expected in [('native_context',owned),('original_native_context',prior),('source_context7',candidate['sdk_context_expected'])]:
            need({k:{t:v[t] for t in ('sha256','size')} for k,v in phase[key].items()}==expected,'P5 complete phase context differs')
    raw=Path(status['raw']);need(raw.is_absolute(),'Accepted RAW path must be absolute')
    need(set(completion['raw_metadata4'])=={'profile.json','lock.json','firmware-manifest.json','build.config'},'Exactly RAW metadata4 required')
    for name in ('profile.json','lock.json','firmware-manifest.json','build.config'):
        row=completion['raw_metadata4'][name];need(row['path']==str(raw/name) and {k:row[k] for k in ('sha256','size')}==status['native_input_records'][str(raw/name)],'Complete accepted RAW4 custody differs')
        checked(row,json_body=name!='build.config')
    evidence=checked(status['native_evidence']);need(status['native_evidence']['sha256']==status['evidence_sha256'] and evidence['ok'] is True,'Actual independent native evidence differs')
    checked(status['sdk_baseline'])
    bank=Path(path).parent/'native-bank.json';need(record(bank)['sha256']==status['native_bank_sha256'],'Complete native-bank file SHA differs')
    refs[str(bank)]={'path':str(bank),**record(bank)}
    return status,candidate,refs


def source_contexts(status,candidate):
    result={}
    for label,path,context in [('owned',status['source'],candidate['owned_context']),('original',status['original_source'],candidate['original_context'])]:
        root=Path(path);need(root.is_absolute() and root.resolve()==root,'Canonical distinct source required')
        strict={role:record(root/value['path']) for role,value in context['required_files'].items()}
        expected={role:{k:value[k] for k in ('sha256','size')} for role,value in context['required_files'].items()}
        seven={role:record(root/KROOT/role) for role in SEVEN}
        need(strict==expected and seven==candidate['sdk_context_expected'],'Current whole functional source/SDK7 differs')
        result[label]={'functional':strict,'SDK7':seven}
    need(status['source']!=status['original_source'],'Owned/new source must be distinct from old source')
    return result
