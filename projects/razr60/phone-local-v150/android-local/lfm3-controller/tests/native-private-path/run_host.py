#!/usr/bin/env python3
"""Execute real ancestor replacements against both production native IO paths."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,os,subprocess,sys,tempfile
sys.dont_write_bytecode=True
CASES=['canonical_read','canonical_pin','canonical_directory','canonical_scope','canonical_publish',
'unicode_read','traversal_only_ancestor','alias_ancestor_read','alias_final_read','noncanonical_dot',
'noncanonical_dotdot','noncanonical_duplicate','noncanonical_trailing','noncanonical_relative','invalid_utf8_path',
'held_input_ancestor_alias','held_input_replacement','held_publication_parent_alias','held_publication_parent_replacement']
CASES += ['raced_'+action+'_'+kind for action in ['read','pin','directory','scope','publish']
          for kind in ['symlink_foreign','symlink_original','realreplacement']]
VULNERABLE=set(CASES[15:16]+CASES[17:]+[])
VULNERABLE.discard('held_input_replacement')
def need(x,m):
    if not x:raise RuntimeError(m)
def digest(b):return hashlib.sha256(b).hexdigest()
def ref(p):
    b=p.read_bytes();return {'path':str(p),'bytes':len(b),'sha256':digest(b)}
def save(p,value):p.write_text(json.dumps(value,indent=2)+'\n')
def run(source,out,cc,baseline):
    need(sys.platform.startswith('linux') and os.getuid()>0,'ordinary Linux host required')
    source=source.resolve(strict=True);out=out.resolve()
    need(not out.exists() and source!=out and source not in out.parents,'fresh external output')
    out.mkdir(parents=True,mode=0o700)
    members=['native/generate_adapter.py','native/model-runtime.inc','native/publish-appuid.inc',
        'native/worker-upstream.c','native/owned-generation.inc','native/warm-protocol.inc',
        'native/prompt_evidence_adapter.py','native/warm_runtime_adapter.py','native/sdk_exception_adapter.py']
    members += ['native/vlm-worker/native/'+n for n in ['generation-bridge.c','guard-io.h','private-io.inc',
        'owned-generation.inc','parent-death-guard.h','sha256-dispatch.h']]
    before={n:ref(source/n) for n in members}
    need((source/'native/owned-generation.inc').read_bytes()==(source/'native/vlm-worker/native/owned-generation.inc').read_bytes(),'shared containment copy differs')
    need(digest((source/'native/worker-upstream.c').read_bytes())=='07cd434bea9d1214acef499a69ed204ecef879a6ac05c82f24d062160e2efb3e','upstream source changed')
    need(digest((source/'native/vlm-worker/tests/guard-test.c').read_bytes())=='6bd082a746cc30844ddc81a39019ee169be7d700bfa3c786e847e437e5cb491d','original 43 checks changed')
    sys.path.insert(0,str(source/'native'))
    spec=importlib.util.spec_from_file_location('actual_native_adapter',source/'native/generate_adapter.py')
    gen=importlib.util.module_from_spec(spec);spec.loader.exec_module(gen)
    generated=out/'generated';generated.mkdir();gen.generate(source,generated)
    text=(generated/'worker-appuid.c').read_text()
    private=text[text.index('static bool utf8('):text.index('\ntypedef struct {\n    const char *id,*mode,')]
    input_type='typedef struct { const char *path;int fd;struct stat before;unsigned char *bytes;size_t size;char digest[65]; } Input;'
    need(private.count(input_type)==1,'exact generated Input declaration')
    private=private.replace(input_type,'typedef HeptaInput Input;')
    start=text.index('static bool id_ok(')
    private+=text[start:text.index('static bool parse(',start)]
    commands=[];cases=[];extractions={}
    def command(argv,stem):
        p=subprocess.run(list(map(str,argv)),capture_output=True,timeout=30,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
        a=out/(stem+'.stdout');b=out/(stem+'.stderr');a.write_bytes(p.stdout);b.write_bytes(p.stderr)
        row={'command':list(map(str,argv)),'exit_code':p.returncode,'stdout':ref(a),'stderr':ref(b)}
        commands.append(row);return p,row
    p,_=command([cc,'--version'],'compiler-version');need(p.returncode==0,'compiler version')
    for kind in ['vlm','text']:
        work=out/kind;work.mkdir()
        (work/'generation-bridge-under-test.c').write_bytes((source/'native/vlm-worker/native/generation-bridge.c').read_bytes())
        if kind=='vlm':
            (work/'private-io.inc').write_bytes((source/'native/vlm-worker/native/private-io.inc').read_bytes())
            target='#include "generation-bridge-under-test.c"\nstatic HeptaInput pin={.fd=-1};\n'
            target+='static int guard_directory(const char *path){return hv_private_directory(path,NULL);}\n'
            target+='static int guard_pin(const char *path,const char *sha){return hv_pin(&pin,path,3,sha,1,NULL,NULL);}\n'
            target+='static void guard_pin_close(void){hv_free(&pin);}\n'
        else:
            (work/'private-io.inc').write_text(private)
            model=(source/'native/model-runtime.inc').read_text()
            model=model[:model.index('static bool hepta_load_vocabulary(')]
            (work/'model-io-under-test.inc').write_text(model)
            target='#include "generation-bridge-under-test.c"\ntypedef int32_t llama_token;\n'
            target+='static struct { const char *filename,*sha256;uint64_t bytes; } profile;\n'
            target+='static __typeof__(profile) *hepta_model_profile=&profile;\n'
            target+='#define PH_CREATE 1\nstatic bool fence(int phase){return phase==PH_CREATE;}\n#include "model-io-under-test.inc"\n'
            target+='static int guard_directory(const char *path){return hg_private_directory(path);}\n'
            target+='static int guard_pin(const char *path,const char *sha){profile.filename="input";profile.sha256=sha;profile.bytes=3;return hepta_verify_model(path);}\n'
            target+='static void guard_pin_close(void){if(hepta_model_fd>=0)close(hepta_model_fd);hepta_model_fd=-1;(void)canonical;(void)hepta_architecture;(void)hepta_model_unchanged;(void)hepta_vocabulary_model;(void)hepta_input_ids;(void)hepta_input_count;}\n'
        (work/'production-target.inc').write_text(target)
        extractions[kind]={'private_io':ref(work/'private-io.inc'),'target':ref(work/'production-target.inc'),
            'actual_bridge':ref(work/'generation-bridge-under-test.c'),'input_type_only_adapted':kind=='text',
            'model_io':ref(work/'model-io-under-test.inc') if kind=='text' else None}
        fixture=Path(__file__).with_name('race-test.c')
        binary=work/'race-test'
        p,row=command([cc,'-std=c11','-O2','-Wall','-Wextra','-Werror','-I'+str(work),
            '-I'+str(source/'native/vlm-worker/native'),fixture,'-o',binary],kind+'-compile')
        if p.returncode:raise RuntimeError(kind+' compile: '+p.stderr.decode())
        for name in CASES:
            with tempfile.TemporaryDirectory(prefix='hepta-native-private-path-',dir='/tmp') as tmp:
                p,row=command([binary,name,tmp],kind+'-'+name)
                need(p.returncode in (0,1),kind+'/'+name+' fixture failure '+p.stderr.decode())
                result=json.loads(p.stdout);need(result['case']==name and result['passed']==(p.returncode==0),'case receipt differs')
                cases.append({'target':kind,'name':name,'execution':row,'result':result})
    unchanged=before=={n:ref(source/n) for n in members}
    need(unchanged,'production source changed during regression')
    failures=[(c['target'],c['name']) for c in cases if not c['result']['passed']]
    if baseline:
        wanted={(k,n) for k in ['vlm','text'] for n in VULNERABLE}
        need(set(failures)==wanted,'baseline failure set differs: '+repr(failures))
        need(all(c['result']['accepted'] and c['result']['actual_rename_count']==1 for c in cases if not c['result']['passed']),'baseline did not execute vulnerable acceptance')
    else:need(not failures,'fixed-source regression failed: '+repr(failures))
    result={'schema':'hepta.native-private-path.host.v1','passed':not failures,
        'baseline_vulnerability_reproduced':baseline and bool(failures),'source':str(source),'sources':before,
        'sources_unchanged':unchanged,'test':ref(Path(__file__).with_name('race-test.c')),'runner':ref(Path(__file__)),
        'commands':commands,'extractions':extractions,'case_count':len(cases),
        'check_count':sum(c['result']['checks'] for c in cases),'failed_cases':failures,'cases':cases,
        'real_filesystem_executed':True,'sdk_executed':False,'phone_contacted':False,'model_inference_performed':False}
    save(out/'RESULT.json',result)
    print(json.dumps({k:result[k] for k in ['passed','baseline_vulnerability_reproduced','case_count','check_count','failed_cases','sources_unchanged']}))
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True);parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--cc',default='/usr/bin/cc');parser.add_argument('--expect-vulnerable',action='store_true')
    a=parser.parse_args()
    run(a.source,a.out,a.cc,a.expect_vulnerable)
