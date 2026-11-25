#!/usr/bin/env python3
"""Finite current-form publication checks; Android/time ports are explicitly synthetic."""
import argparse, ast, hashlib, importlib.util, json, os, sys
from pathlib import Path
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
PKG = Path("src/org/trillionnium/hepta/local")
BASE_RUNNER_SHA = "bb0d7270d496149d517233baab212f0276143c150f26f5455934424728c26dcd"
def sha(b): return hashlib.sha256(b).hexdigest()
def module(p, name):
    spec = importlib.util.spec_from_file_location(name,p)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
def once(s,a,b):
    if s.count(a)!=1: raise RuntimeError("exact fixture anchor: "+a[:100])
    return s.replace(a,b,1)
def bridge(prior):
    s=prior
    s=once(s,"    static final String TEST_SHA=NativeActionSnapshotCheckHostTest.H;\n",
        '    static final String TEST_SHA=NativeActionSnapshotCheckHostTest.H;\n'
        '    static final int FORM_DISPLAY=Integer.getInteger("hepta.form.display",15);\n'
        '    static final int FORM_WINDOW=Integer.getInteger("hepta.form.window",96);\n')
    # Host endpoint adaptation only. The complete private node values are not rewritten.
    for old,new in [(",15,window,",",FORM_DISPLAY,window,"),('row.put("window_id",96)','row.put("window_id",FORM_WINDOW)'),
        ('row.put("display_id",15)','row.put("display_id",FORM_DISPLAY)'),('out.put("display_id",15)','out.put("display_id",FORM_DISPLAY)'),
        ('out.put("target_window_id",96)','out.put("target_window_id",FORM_WINDOW)'),("g.windowId=96;","g.windowId=FORM_WINDOW;"),
        ('"android.widget.FrameLayout",1,15,','"android.widget.FrameLayout",1,FORM_DISPLAY,'),
        ("new BackgroundSession(15)","new BackgroundSession(FORM_DISPLAY)"),
        ("noteObservationEvent(15,96,","noteObservationEvent(FORM_DISPLAY,FORM_WINDOW,"),
        ("noteObservationEvent(15,97,","noteObservationEvent(FORM_DISPLAY,FORM_WINDOW+1,"),
        ("noteObservationEvent(15)","noteObservationEvent(FORM_DISPLAY)"),
        ("owned(bg.profile,96,","owned(bg.profile,FORM_WINDOW,"),
        ("g.windowId=97;","g.windowId=FORM_WINDOW+1;"),
        ("f.taskBackground.generation,15,","f.taskBackground.generation,FORM_DISPLAY,")]:
        if old not in s: raise RuntimeError("fixture endpoint absent: "+old)
        s=s.replace(old,new)
    s=once(s,'        final boolean region=scenario.startsWith("post_region");\n',
        '        final boolean readLate=scenario.startsWith("read_late_");\n'
        '        final boolean region=scenario.startsWith("post_region");\n')
    s=once(s,'final NativeActionSnapshotCheckHostTest.Fixture before=region?regionFixture(false):FormPairHostTest.managedForm();',
        'final NativeActionSnapshotCheckHostTest.Fixture before=readLate?readLateFixture(false,null):region?regionFixture(false):FormPairHostTest.managedForm();')
    s=once(s,'final NativeActionSnapshotCheckHostTest.Fixture after=region?regionFixture(true):FormPairHostTest.changedForm(before);',
        'final NativeActionSnapshotCheckHostTest.Fixture after=readLate?readLateFixture(true,before):region?regionFixture(true):FormPairHostTest.changedForm(before);')
    s=once(s,'boolean post=scenario.startsWith("post_")||scenario.equals("ordinary_late_change");',
        'boolean post=scenario.startsWith("post_")||scenario.equals("ordinary_late_change")||readLate;')
    s=once(s,'boolean late=scenario.startsWith("post_late")||scenario.equals("ordinary_late_change");',
        'boolean late=scenario.startsWith("post_late")||scenario.equals("ordinary_late_change")||readLate;')
    s=once(s,'                if(changed){\n',
        '''                if(readLate&&n==7){
                    if(scenario.equals("read_late_boundary"))f.noteObservationEvent(FORM_DISPLAY,FORM_WINDOW,NativeAppGoal.CTRIP_PACKAGE,false);
                    if(scenario.endsWith("unknown"))f.noteObservationEvent(-1);
                    if(scenario.endsWith("during_content"))f.noteObservationEvent(FORM_DISPLAY,FORM_WINDOW,NativeAppGoal.CTRIP_PACKAGE,true);
                    if(scenario.endsWith("main_event"))f.noteObservationEvent(0,71,"synthetic.other.app",true);
                    if(scenario.endsWith("late_content"))f.afterReadHook=()->f.noteObservationEvent(FORM_DISPLAY,FORM_WINDOW,NativeAppGoal.CTRIP_PACKAGE,true);
                    if(scenario.endsWith("late_boundary"))f.afterReadHook=()->f.noteObservationEvent(FORM_DISPLAY,FORM_WINDOW,NativeAppGoal.CTRIP_PACKAGE,false);
                    if(scenario.endsWith("date"))replaceNode(graph,"0/0/2/5","text","11月28日周六");
                    if(scenario.endsWith("overlap")){
                        String anchor=System.getProperty("hepta.form.variable.root","0/0/7");
                        replaceNode(graph,anchor,"bounds",Arrays.asList(79,793,415,937));
                    }
                    if(scenario.endsWith("omission"))graph.collectionStats=counters(graph,graph.nativeActionNodes.size(),0,1,0);
                    if(scenario.endsWith("owner"))graph.backgroundOwnerSha=NativeActionSnapshotCheckHostTest.repeat('d',64);
                    if(scenario.endsWith("window"))graph.windowId=FORM_WINDOW+1;
                    if(scenario.endsWith("display"))graph.displayId=FORM_DISPLAY+1;
                    if(scenario.endsWith("user")){
                        ProfileTarget other=new ProfileTarget(new ProfileIdentity(11,8L,0,ProfileIdentity.MANAGED),1112345,
                            NativeAppGoal.CTRIP_PACKAGE,NativeAppGoal.CTRIP_PACKAGE+"/SyntheticActivity",NativeCtripFlightPage.VERSION_CODE,
                            Collections.singletonMap("base",NativeCtripFlightPage.BASE_APK_SHA256),Collections.singleton(TEST_SHA));
                        graph.profileWindow=owned(other,FORM_WINDOW,TEST_TOKEN);
                    }
                    if(scenario.endsWith("read_before"))f.current=null;
                    if(scenario.endsWith("cancel"))f.cancelled.set(true);
                    if(scenario.endsWith("deadline"))SystemClock.now=f.activeObservation.deadline;
                }
                if(changed){
''')
    s=once(s,'if(scenario.startsWith("post_late")||scenario.equals("ordinary_late_change")||scenario.equals("post_early_event_after_pair"))',
        'if(scenario.startsWith("post_late")||scenario.equals("ordinary_late_change")||scenario.equals("post_early_event_after_pair")||scenario.startsWith("read_late_"))')
    s=once(s,'            ObservationRequest request=f.captureFormRead();long captureAt=f.lastScreenshotAt;\n',
        '''            if(scenario.equals("read_late_sidecar_content"))f.formHistoryHashHook=()->f.noteObservationEvent(FORM_DISPLAY,FORM_WINDOW,NativeAppGoal.CTRIP_PACKAGE,true);
            ObservationRequest request=f.captureFormRead();long captureAt=f.lastScreenshotAt;
''')
    s=once(s,'            f.main.drain();\n            out.put("original_frame_id",before.id);\n',
        '''            if(scenario.equals("read_late_main_handoff"))f.noteObservationEvent(FORM_DISPLAY,FORM_WINDOW,NativeAppGoal.CTRIP_PACKAGE,true);
            f.main.drain();
            if(request.trace!=null){
                String diagnostic=new DiagnosticSnapshot(request.trace).call();
                out.put("diagnostic_json_bytes",diagnostic.getBytes(StandardCharsets.UTF_8).length);
                out.put("diagnostic_snapshot",new org.json.JSONObject(diagnostic).toMap());
                out.put("diagnostic_original",request.trace.snapshot(SystemClock.now));
            }
            out.put("original_frame_id",before.id);
''')
    s=s.replace('f.current==before||"read_before_replaced".equals(scenario)&&f.current==null',
        'f.current==before||("read_before_replaced".equals(scenario)||"read_late_read_before".equals(scenario))&&f.current==null')
    s += r'''
    static NativeActionSnapshotCheckHostTest.Fixture readLateFixture(boolean after,NativeActionSnapshotCheckHostTest.Fixture before)throws Exception{
        String path=System.getProperty("hepta.form.raw.census");
        if(path==null)return after?FormPairHostTest.changedForm(before):FormPairHostTest.managedForm();
        org.json.JSONObject input=new org.json.JSONObject(new String(Files.readAllBytes(Paths.get(path)),StandardCharsets.UTF_8));
        org.json.JSONArray rows=input.getJSONObject(after?"after":"before").getJSONArray("native_nodes");
        NativeActionSnapshotCheckHostTest.Fixture value=FormPairHostTest.managedForm();value.nodes.clear();
        for(int i=0;i<rows.length();i++){
            Map<String,Object> node=rows.getJSONObject(i).toMap();
            if(!NativeAppGoal.CTRIP_PACKAGE.equals(node.get("package"))||((Number)node.get("window_id")).intValue()!=FORM_WINDOW)
                throw new AssertionError("actual node identity differs from explicit endpoint");
            value.nodes.put((String)node.get("path"),node);
        }
        return value;
    }
'''
    return s
def main():
    ap=argparse.ArgumentParser()
    for n in ("source","output","java-home","json-jar"):ap.add_argument("--"+n,type=Path,required=True)
    ap.add_argument("--actual-census",type=Path);ap.add_argument("--actual-census-sha256")
    a=ap.parse_args();source=a.source.resolve();output=a.output.absolute();output.mkdir(parents=True,exist_ok=False)
    old=source/"tests/native-ctrip-form-observation/run_observer_host.py"
    if sha(old.read_bytes())!=BASE_RUNNER_SHA:raise RuntimeError("original observer source exact pin")
    m=module(old,"finite_form_observer");h=module(source/"tests/observation-diagnostics/run_host.py","finite_form_helpers")
    prior=m.BRIDGE;m.BRIDGE=bridge(prior)
    java=a.java_home/"bin/java";javac=a.java_home/"bin/javac";jar=a.json_jar
    if jar.stat().st_size!=78332 or sha(jar.read_bytes())!="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed":
        raise RuntimeError("JSON exact pin")
    inputs=[source/PKG/n for n in m.JAVA+m.READ]+[source/m.PROFILE/n for n in m.PROFILE_NAMES]
    inputs += [source/m.TEST/n for n in ("ObserverIntegrationHostTest.java","run_observer_host.py","FormPairHostTest.java","scope_predecessor.py","form-region-nodes.json")]
    inputs += [source/"tests/native-action-integration/NativeActionSnapshotCheckHostTest.java",
        source/"tests/observation-pipeline/ObserverPipelineHost.template",source/"tests/observation-diagnostics/run_host.py",
        source/"tests/native-xiaomi-query-stability/protected_filled_query.py",HERE/"run_host.py",HERE/"FormReadPublicationHostTest.java"]
    inputs += h.png_sources(source)
    tools=[java,javac,a.java_home/"lib/modules",a.java_home/"lib/ct.sym",jar]
    props=[]
    actual_meta=None
    if a.actual_census is not None:
        if a.actual_census.is_symlink() or not a.actual_census_sha256 or sha(a.actual_census.read_bytes())!=a.actual_census_sha256:
            raise RuntimeError("actual complete census exact ref")
        raw=json.loads(a.actual_census.read_text())
        if raw.get("complete_pair_recorded") is not True or raw.get("raw_pair_omitted_for_budget") is not False:
            raise RuntimeError("complete actual private pair required")
        x,z=raw["before"],raw["after"]
        if x["identity"]!=z["identity"] or not x["native_nodes_complete"] or not z["native_nodes_complete"]:
            raise RuntimeError("actual same identity complete pair required")
        before={v["path"]:v for v in x["native_nodes"]};after={v["path"]:v for v in z["native_nodes"]}
        changed=[p for p in sorted(set(before)|set(after)) if before.get(p)!=after.get(p)]
        common=changed[0]
        while any(p!=common and not p.startswith(common+"/") for p in changed):common=common.rsplit("/",1)[0]
        props=["-Dhepta.form.raw.census="+str(a.actual_census),"-Dhepta.form.window="+str(x["identity"]["window_id"]),
            "-Dhepta.form.display="+str(x["identity"]["display_id"]),"-Dhepta.form.variable.root="+common,
            "-Dhepta.form.expected.nodes="+str(len(before)),"-Dhepta.form.expected.changes="+str(len(changed))]
        inputs += [a.actual_census]
        actual_meta={"file":h.meta(a.actual_census),"nodes":[len(before),len(after)],"changed_paths":changed,
            "original_nodes_rewritten":False,"event_watermarks":"synthetic; not present in historical archive",
            "clock_and_android_authority":"synthetic ports; not historical device replay or effect authority"}
    before=[h.meta(p) for p in inputs];tb=[h.meta(p) for p in tools]
    report={"schema":"hepta.ctrip-current-form-publication-host.v1","all_pass":False,"source_root":str(source),
        "stages":[],"source_inputs":before,"tools_before":tb,"actual_census":actual_meta,
        "fixture_bridge":{"original_sha256":sha(prior.encode()),"derived_sha256":sha(m.BRIDGE.encode())},
        "phone_operations":0,"android_execution":False,"model_executed":False,"business_completion_verified":False,
        "historical_event_watermarks_reconstructed":False,"existing_68_cases_reexecuted":False}
    try:
        generated=output/"generated";generated.mkdir();extraction=m.generate(source,generated,h)
        extraction["original_observer_methods_and_hooks_verbatim"]=False
        extraction["fixture_extension"]="finite ordinary post-encoding form cases; production extracted parts remain actual"
        h.save(output/"EXTRACTION.json",extraction)
        classes=output/"classes";classes.mkdir()
        compiled=[source/PKG/n for n in m.JAVA]+[source/m.PROFILE/n for n in m.PROFILE_NAMES]
        compiled += [source/"tests/native-action-integration/NativeActionSnapshotCheckHostTest.java",
            source/m.TEST/"FormPairHostTest.java",source/m.TEST/"ObserverIntegrationHostTest.java",
            generated/"ObserverPipelineHost.java",HERE/"FormReadPublicationHostTest.java"]
        compiled += h.png_sources(source)
        report["stages"].append(h.stage("compile",[str(javac),"--release","8","-encoding","UTF-8","-Xlint:all","-Werror","-cp",str(jar),"-d",str(classes)]+[str(p) for p in compiled],output))
        if report["stages"][-1]["exit_code"]!=0:raise RuntimeError("finite actual observer compilation failed")
        report["stages"].append(h.stage("finite-cases",[str(java)]+props+["-cp",str(classes)+os.pathsep+str(jar),
            "org.trillionnium.hepta.local.FormReadPublicationHostTest",str(output/"CASES.json")],output))
        cases=json.loads((output/"CASES.json").read_text());report["cases"]=cases;report["case_file"]=h.meta(output/"CASES.json")
        report["extraction_file"]=h.meta(output/"EXTRACTION.json")
        report["generated_files"]={p.name:h.meta(p) for p in generated.glob("*.java")}
        if report["stages"][-1]["exit_code"]!=0 or cases["all_pass"] is not True:raise RuntimeError("finite cases failed")
        report["all_pass"]=True
    except Exception as error:report["error"]={"type":type(error).__name__,"message":str(error)}
    finally:
        report["source_inputs_after"]=[h.meta(p) for p in inputs];report["tools_after"]=[h.meta(p) for p in tools]
        report["inputs_unchanged"]=before==report["source_inputs_after"];report["tools_unchanged"]=tb==report["tools_after"]
        report["all_pass"]=report["all_pass"] and report["inputs_unchanged"] and report["tools_unchanged"]
        h.save(output/"RESULT.json",report)
    print(json.dumps({"all_pass":report["all_pass"],"result":h.meta(output/"RESULT.json")},sort_keys=True))
    return 0 if report["all_pass"] else 1
if __name__=="__main__":raise SystemExit(main())
