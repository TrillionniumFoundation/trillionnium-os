#!/usr/bin/env python3
"""Exercise the production visual metadata projection; no phone/network/model."""
import argparse, hashlib, json, shutil, subprocess, sys
from pathlib import Path

def pin(path):
    raw=path.read_bytes()
    return {'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--json-jar',type=Path,required=True)
    p.add_argument('--java',default=shutil.which('java'))
    p.add_argument('--javac',default=shutil.which('javac'))
    p.add_argument('--release8',action='store_true')
    p.add_argument('--replay-prompt',type=Path,action='append',default=[])
    a=p.parse_args();root=a.source.resolve();out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    production=root/'src/org/trillionnium/hepta/local/VisualPromptProjection.java'
    test=root/'tests/visual-prompt-projection/VisualPromptProjectionHostTest.java'
    jar=a.json_jar.resolve();jar_pin=pin(jar)
    report={'schema':'hepta.visual-prompt-projection.host.v1','passed':False,'phone_contacted':False,
            'model_inference_performed':False,'exact_token_count_measured':False,'java8_api_checked':a.release8,'commands':[],
            'sources':{str(q.relative_to(root)):pin(q) for q in (production,test)},'json_jar':jar_pin,'replays':[]}
    def run(name,argv):
        r=subprocess.run(list(map(str,argv)),capture_output=True,timeout=60)
        (out/(name+'.stdout')).write_bytes(r.stdout);(out/(name+'.stderr')).write_bytes(r.stderr)
        report['commands'].append({'name':name,'argv':list(map(str,argv)),'exit_code':r.returncode,
            'stdout':pin(out/(name+'.stdout')),'stderr':pin(out/(name+'.stderr'))})
        if r.returncode:raise RuntimeError(name+' failed')
        return r.stdout
    try:
        if not a.java or jar_pin['bytes']!=78332 or jar_pin['sha256']!='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed':
            raise ValueError('existing Java and exact host JSON dependency required')
        classes=out/'classes';classes.mkdir()
        compiler=[a.javac] if a.javac else [a.java,'-XX:-UsePerfData','-m','jdk.compiler/com.sun.tools.javac.Main']
        version=['--release','8'] if a.release8 else ['-source','8','-target','8','-Xlint:-options']
        run('compile',compiler+['-encoding','UTF-8','-Xlint:all','-Werror']+version+['-cp',jar,'-d',classes,production,test])
        command=[a.java,'-XX:-UsePerfData','-cp',str(classes)+':'+str(jar),'org.trillionnium.hepta.local.VisualPromptProjectionHostTest']
        result=json.loads(run('execute',command))
        if result.get('passed') is not True or result.get('checks',0)<40:raise ValueError('projection test did not complete')
        report['result']=result
        system=run('system-text',command+['--system-text'])
        report['visual_system_utf8_bytes']=len(system)
        report['visual_system_sha256']=hashlib.sha256(system).hexdigest()
        for i,path in enumerate(a.replay_prompt):
            raw=path.read_bytes();text=raw.decode('utf-8');prefix='UNTRUSTED_DATA\n';boundary='\nOWNER\n'
            if not text.startswith(prefix) or boundary not in text:raise ValueError('original prompt envelope unavailable')
            data_text,owner=text[len(prefix):].split(boundary,1);data=json.loads(data_text)
            src=out/('replay-%02d-source.json'%i);src.write_text(json.dumps(data,ensure_ascii=False),encoding='utf-8')
            projected=json.loads(run('replay-%02d'%i,command+['--project-json',src]))
            for name in ('screen','events','last_transition','last_model_decision','apps','open_allowed_packages','blocked','format_correction'):
                if name in data and data[name]!=projected.get(name):raise ValueError('actual prompt semantic content changed: '+name)
            # Recreate the controller envelope and original section order. These
            # byte counts are not presented as native tokenizer measurements.
            sections=',\n'.join(json.dumps({k:projected[k]},ensure_ascii=False,separators=(',',':'))[1:-1] for k in data)
            generated=prefix+'{\n'+sections+'\n}'+boundary+owner
            dest=out/('replay-%02d-model-prompt.txt'%i);dest.write_text(generated,encoding='utf-8')
            report['replays'].append({'original':pin(path),'projected':pin(dest),
                'original_data_utf8_bytes':len(data_text.encode()),'projected_data_utf8_bytes':len(('{\n'+sections+'\n}').encode()),
                'owner_exact':generated.split(boundary,1)[1]==owner,'screen_and_history_exact':True,
                'native_token_count_measured':False,'grammar_or_dispatch_executed':False,
                'byte_count_scope':'host JSON serialization; Android serialization and native token counts require device run'})
        report['sources_unchanged']=all(pin(root/k)==v for k,v in report['sources'].items())
        if not report['sources_unchanged']:raise ValueError('source changed during host run')
        report['passed']=True
    except Exception as error:report['error']=str(error)
    finally:
        (out/'RESULT.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
        print(json.dumps({'passed':report['passed'],'result':report.get('result'),'error':report.get('error'),
                          'replays':[{'original_bytes':r['original']['bytes'],'projected_bytes':r['projected']['bytes']} for r in report['replays']]}))
    return 0 if report['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
