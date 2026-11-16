#!/usr/bin/env python3
"""Isolated pure parser regression. No Android, device, SDK or dispatch.

The current source is compiled afresh. Optional --previous-source reproduces
the original unrecognized-page outcome from the exact b95f parser. Saved frame
JSON remains the authoritative input; the small Java DTO fixture is verified
against its exact fields before compilation.
"""
import argparse, hashlib, json, os, re, subprocess, time
from pathlib import Path

OLD='b95f57c9e1b8d0f89b3e6e80ee1495113e0ea1069fe2805e1dcb461092e73cb2'
PACKAGE='src/org/trillionnium/hepta/local/'
TESTS='tests/native-xiaomi-image-modal/'

def need(v, why):
    if not v: raise ValueError(why)

def record(p):
    p=Path(p);data=p.read_bytes()
    return {'path':str(p),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}

def write(p, obj):
    with Path(p).open('x',encoding='utf-8') as f:
        json.dump(obj,f,ensure_ascii=False,sort_keys=True,indent=2);f.write('\n')

def fixture(test):
    root=test/'fixtures';prov=json.loads((root/'PROVENANCE.json').read_text())
    for row in prov['files']:
        actual=record(root/row['file']);need(all(actual[k]==row[k] for k in ('bytes','sha256')),'original fixture identity changed')
    o=json.loads((root/'actual-observation.json').read_text());m=json.loads((root/'actual-page.json').read_text())['frame']
    b=json.loads((root/'actual-binding.json').read_text());owner=prov['owner']
    need(m['phone_observation_record_sha256']==record(root/'actual-observation.json')['sha256'],'page/raw linkage')
    need(m['owner_sha256']==b['owner_sha256']==hashlib.sha256(owner.encode()).hexdigest(),'exact OWNER linkage')
    need(m['observation_id']==o['observation_id'] and m['retained_nodes']==len(o['nodes'])==2,'actual retained graph')
    c=o['collection'];need(c['visited_nodes']==3 and c['retained_nodes']==2 and c['retained_text_utf16']==0,'actual collector counters')
    need(c['pending_nodes_at_stop']==c['child_slots_omitted_by_traversal_limit']==c['nodes_omitted_by_node_limit']==c['nodes_omitted_by_text_limit']==0,'complete original traversal')
    need(o['nodes_truncated'] is False and c['truncation_reasons']==[] and m['actual_collection_complete'] is True,'actual collection completeness')
    q=lambda s:json.dumps(s,ensure_ascii=False)
    def boolean(v):
        need(type(v) is bool,'real Boolean required');return str(v).lower()
    rows=[]
    for n in o['nodes']:
        need(n['child_text_status']=='empty' and n['child_text_sources_complete'] is True and n['child_text_truncated'] is False,'actual label is empty')
        need(n['scroll_directions']==[] and n['native_selection_state']['observed'] is True,'actual scroll/selection tuple')
        need(all(n.get(k,'')=='' for k in ('text','description','child_text','view_id')),'fixture is the saved empty-label modal')
        t=n['native_tree_position'];s=n['native_selection_state']
        vals=[q(n['id']),q(n['package']),q(n['class_name']),q(n.get('view_id','')),q(n.get('text','')),q(n.get('description','')),q(t['path']),q(t['parent_class']),q(n['node_app_tree_sha256']),q('')]
        vals+=list(map(str,n['bounds']))+[boolean(n.get('enabled',True)),boolean(n.get('password',False)),boolean(n.get('clickable',False)),boolean(n.get('editable',False)),boolean(n.get('scrollable',False))]
        vals+=['Boolean.'+str(s[k]).upper() for k in ('selected','checkable','checked')]+['Collections.<String>emptySet()']
        rows.append('        nodes.add(new NativeAppEvidence.Node('+',\n                '.join([','.join(vals[:10]),','.join(vals[10:])])+'));')
    strings=[m[k] for k in ('task_id','owner_sha256','execution_target_sha256','task_authorization_sha256','actual_selection_sha256','observation_id','package','background_generation','app_tree_sha256','observation_state_sha256','screen_sha256','phone_observation_record_sha256','completion_frame_sha256')]
    args=','.join(map(q,strings))+',\n                '+','.join(map(str,[m['display_id'],m['window_id'],o['rotation'],o['screen_width'],o['screen_height']]+o['window']['bounds']))+',\n                '+str(m['captured_elapsed_ms'])+'L,false,true,nodes,1,true'
    actual=(test/'ActualXiaomiImageModalFixture.java').read_text()
    need('    static final String OWNER='+q(owner)+';' in actual,'fixture OWNER literal')
    need('    static final String ORIGINAL_SHA='+q(m['phone_observation_record_sha256'])+';' in actual,'fixture raw SHA literal')
    start=actual.index('        nodes.add(');end=actual.index('\n    }',start)
    need(actual[start:end]=='\n'.join(rows)+'\n        return new NativeAppEvidence.Frame('+args+');','all generated DTO fields match saved JSON')
    return {'original_frame':record(root/'actual-observation.json'),'original_page':record(root/'actual-page.json'),
            'original_binding':record(root/'actual-binding.json'),'all_DTO_fields_match_original':True,
            'json_defaults_source':'PhoneObservation.Node.json: absent enabled=true; absent password/editable/scrollable=false; absent text/description/view_id empty. NativeAppObservation explicitly clears non-derived empty child labels.',
            'live_android_adapter_executed':False}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--source',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--java-home',type=Path,required=True);ap.add_argument('--previous-source',type=Path)
    a=ap.parse_args();src=a.source.resolve(strict=True);out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    home=a.java_home.resolve(strict=True);java=home/'bin/java';javac=home/'bin/javac';test=src/TESTS
    compile_prefix=[str(javac)] if javac.is_file() else [str(java),'--module','jdk.compiler/com.sun.tools.javac.Main']
    need(java.is_file(),'real Java runtime required')
    ct=home/'lib/ct.sym';release=ct.is_file()
    flags=['--release','8','-Xlint:all','-Werror'] if release else ['-source','8','-target','8','-Xlint:all,-options','-Werror']
    deps=[src/PACKAGE/n for n in ('NativeAppGoal.java','NativeAppEvidence.java','NativeXiaomiProductPage.java')]
    tests=[test/n for n in ('ActualXiaomiImageModalFixture.java','NativeXiaomiImageModalHostTest.java')]
    inputs=deps+tests+[Path(__file__).resolve()]+sorted((test/'fixtures').iterdir())
    if a.previous_source:
        old=a.previous_source.resolve(strict=True)/PACKAGE/'NativeXiaomiProductPage.java';need(record(old)['sha256']==OLD,'exact original b95f source required');inputs.append(old)
    tools=[java.resolve(),home/'lib/modules',home/'lib/server/libjvm.so',home/'release']
    if javac.is_file():tools.append(javac.resolve())
    if release:tools.append(ct)
    before=[record(p) for p in inputs];tool_before=[record(p) for p in tools]
    r={'schema':'hepta.native-xiaomi-image-modal-host.v1','all_pass':False,'steps':[],'source_inputs':before,'tool_inputs':tool_before,
       'compiler_api_scope':'Java 8 release APIs' if release else 'host Java APIs; Java 8 syntax/bytecode only (ct.sym absent)',
       'phone_operations':0,'SDK_loaded':False,'android_runtime':False,'business_verified':False,'existing_xiaomi_33_cases_modified':False}
    env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','TZ':'UTC'}
    def run(name,argv):
        started=time.monotonic();p=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,cwd=str(src),timeout=60)
        so=out/(name+'.stdout');se=out/(name+'.stderr');so.write_bytes(p.stdout);se.write_bytes(p.stderr)
        r['steps'].append({'name':name,'argv':argv,'exit_code':p.returncode,'elapsed_seconds':time.monotonic()-started,'stdout':record(so),'stderr':record(se)})
        need(p.returncode==0,name+' failed; original streams retained')
    try:
        r['fixture_projection']=fixture(test)
        current=out/'classes';current.mkdir()
        run('compile',compile_prefix+flags+['-encoding','UTF-8','-d',str(current)]+list(map(str,deps+tests)))
        run('cases',[str(java),'-cp',str(current),'org.trillionnium.hepta.local.NativeXiaomiImageModalHostTest',str(out/'CASES.json')])
        r['cases']=json.loads((out/'CASES.json').read_text());need(r['cases']['cases']==29 and len(set(r['cases']['names']))==29,'complete declared 29 cases')
        if a.previous_source:
            previous=out/'previous-classes';previous.mkdir()
            run('previous-compile',compile_prefix+flags+['-encoding','UTF-8','-d',str(previous)]+list(map(str,deps[:2]+[old]+tests)))
            run('previous-cases',[str(java),'-cp',str(previous),'org.trillionnium.hepta.local.NativeXiaomiImageModalHostTest',str(out/'PREVIOUS-CASES.json'),'legacy'])
            r['previous_cases']=json.loads((out/'PREVIOUS-CASES.json').read_text())
        r['source_inputs_after']=[record(p) for p in inputs];r['tool_inputs_after']=[record(p) for p in tools]
        r['inputs_unchanged']=r['source_inputs_after']==before and r['tool_inputs_after']==tool_before
        need(r['inputs_unchanged'],'source/tool bytes changed');r['all_pass']=True
    except Exception as e:r['error']=type(e).__name__+': '+str(e)
    write(out/'RESULT.json',r);print(json.dumps({'all_pass':r['all_pass'],'result':record(out/'RESULT.json')},sort_keys=True))
    return 0 if r['all_pass'] else 1

if __name__=='__main__':raise SystemExit(main())
