#!/usr/bin/env python3
"""Small pure-Java gate for actual extracted MainActivity probe methods, no Android or inference."""
from pathlib import Path
import argparse,json,hashlib,re,subprocess,os,time,sys
sys.dont_write_bytecode=True
def pin(p):
    p=Path(p);b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def dump(p,v):
    with p.open('x') as f:json.dump(v,f,indent=2);f.write('\n')
def extract(text):
    a=text.index('    private void runProbe(');b=text.index('    private boolean selectedIndependentProfileDisplay()',a)
    block=text[a:b]
    owner=re.findall(r'runText\.setOnClickListener\(v -> (runProbe\([^\n]*?\))\);',text)
    intent=re.findall(r'probePrompt\.post\(\(\) -> (runProbe\([^\n]*?\))\);',text)
    if len(owner)!=1 or len(intent)!=1:raise ValueError('unique actual call expressions required')
    return block,owner[0],intent[0]
def main():
    ap=argparse.ArgumentParser()
    for n in ('source','baseline','output','java-home'):ap.add_argument('--'+n,type=Path,required=True)
    a=ap.parse_args();s=a.source.resolve();b=a.baseline.resolve();out=a.output.absolute();jdk=a.java_home.resolve()
    out.mkdir(parents=True,exist_ok=False);own=Path(__file__).resolve().parent
    rel='src/org/trillionnium/hepta/local/MainActivity.java'
    tracked=[s/rel,b/rel,own/'ProbeTokenBudgetHostTest.template',Path(__file__).resolve(),jdk/'bin/javac',jdk/'bin/java']
    before=[pin(p) for p in tracked];candidate=(s/rel).read_text();baseline=(b/rel).read_text()
    cb,co,ci=extract(candidate);bb,bo,bi=extract(baseline)
    assert co=='runProbe(false,128,true)' and bo=='runProbe(false,128)' and ci==bi=='runProbe(image,max)'
    delegate='    private void runProbe(boolean image,int maxTokens){\n        runProbe(image,maxTokens,false);\n    }\n'
    inverse=cb.replace(delegate,'',1).replace('private void runProbe(boolean image,int maxTokens,boolean ownerTextButton)','private void runProbe(boolean image,int maxTokens)',1).replace('            if(ownerTextButton&&engine.configuration().profile==ModelProfile.LFM25_8B_A1B)maxTokens=256;\n','',1)
    assert inverse==bb,'all original probe control flow must be exact outside the explicit budget delta'
    ia=baseline.index('    private void handleIntent(');iz=baseline.index('    private void chooseModelFileFromOwnerButton()',ia)
    ca=candidate.index('    private void handleIntent(');cz=candidate.index('    private void chooseModelFileFromOwnerButton()',ca)
    assert baseline[ia:iz]==candidate[ca:cz],'complete original Intent method unchanged'
    env=dict(os.environ)
    for k in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH','PYTHONPATH'):env.pop(k,None)
    env.update(JAVA_HOME=str(jdk),PATH=str(jdk/'bin')+':/usr/bin:/bin',PYTHONDONTWRITEBYTECODE='1')
    result=dict(schema='hepta.owner-text-probe-budget-host-gate.v1',all_pass=False,phone_operations=0,android_runtime=False,native_inference=False,fixture_boundary='Exact production runProbe overload bodies plus actual UI/Intent call expressions; engine, Intent, views and callbacks are synthetic.',source_inputs_before=before,source_checks=dict(original_probe_flow_inverse_byte_exact=True,complete_intent_method_byte_exact=True,two_parameter_call_signature_preserved=True,two_parameter_method_body_changed_to_delegate=True),stages=[])
    try:
        template=(own/'ProbeTokenBudgetHostTest.template').read_text()
        for kind,block,owner,intent in [('baseline',bb,bo,bi),('candidate',cb,co,ci)]:
            d=out/kind;d.mkdir();classes=d/'classes';classes.mkdir()
            java=d/'ProbeTokenBudgetHostTest.java'
            java.write_text(template.replace('{{PRODUCTION_METHODS}}',block).replace('{{OWNER_CALL}}',owner).replace('{{INTENT_CALL}}',intent))
            for stage,argv in [('compile',[jdk/'bin/javac','--release','8','-encoding','UTF-8','-Xlint:all','-Werror','-proc:none','-d',classes,java]),('run',[jdk/'bin/java','-ea','-cp',classes,'org.trillionnium.hepta.local.ProbeTokenBudgetHostTest'])]:
                argv=list(map(str,argv));t=time.monotonic()
                with (d/(stage+'.stdout')).open('xb') as so,(d/(stage+'.stderr')).open('xb') as se:
                    p=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=so,stderr=se,env=env,cwd=d,timeout=90)
                row=dict(kind=kind,stage=stage,argv=argv,exit_code=p.returncode,elapsed_seconds=time.monotonic()-t,stdout=pin(d/(stage+'.stdout')),stderr=pin(d/(stage+'.stderr')),extracted_source=pin(java))
                result['stages'].append(row)
                if kind=='baseline' and stage=='run':
                    assert p.returncode!=0 and 'LFM8 ordinary button requires 256' in (d/'run.stderr').read_text(),'original 128 must fail the new requested 256 behavior'
                    result['baseline_expected_red']=True
                else:
                    assert p.returncode==0,kind+' '+stage+' failed'
                    if stage=='run':
                        v=json.loads((d/'run.stdout').read_text());assert v['passed'] is True and v['cases']==15 and v['phone_operations']==0
                        result['candidate_cases']=v['cases'];result['candidate_assertions']=v['assertions']
        result['all_pass']=True
    except BaseException as e:result['error']=type(e).__name__+': '+str(e)
    finally:
        result['source_inputs_after']=[pin(p) for p in tracked];result['source_inputs_unchanged']=before==result['source_inputs_after']
        result['all_pass']=result['all_pass'] and result['source_inputs_unchanged']
        dump(out/'RESULT.json',result)
    print(json.dumps(dict(all_pass=result['all_pass'],result=pin(out/'RESULT.json'),error=result.get('error'))))
    return 0 if result['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
