#!/usr/bin/env python3
"""Compile whole production parser/capture classes; old 75 cases stay byte exact.
Public shapes are synthetic carriers. Optional private replay consumes pinned
original receipt/after/profile/owner archives without any device access.
"""
from pathlib import Path
import argparse,hashlib,json,os,runpy,stat,subprocess,time,traceback
PKG="src/org/trillionnium/hepta/local/"
TEST="tests/native-xiaomi-direct-card/"
JSON_SHA="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
PIN_DATA={'src/org/trillionnium/hepta/local/NativeAppGoal.java': {'bytes': 21582, 'sha256': '9f823e54fee2862e390df6b86d7a2fc9a02d463c073159dc6f38d6c3a31cb5c4'}, 'src/org/trillionnium/hepta/local/NativeAppEvidence.java': {'bytes': 21731, 'sha256': 'b712a70ab60324fed6ae7f221ac2e4b7b414d57cc6bba50213fa4973de6dbb14'}, 'src/org/trillionnium/hepta/background/ProfileIdentity.java': {'bytes': 2811, 'sha256': '7c170e15deb8407a80b4dbcab3564697d2192c63365bb5a062ecba6f3ebbadcd'}, 'src/org/trillionnium/hepta/background/ProfileTarget.java': {'bytes': 6796, 'sha256': '268dc50e7d3205cc8fb35883843fbdf8a10cc517f773867a9aae6d00fe07f2fd'}, 'src/org/trillionnium/hepta/background/WindowOwnership.java': {'bytes': 5829, 'sha256': '60ccf09113a3463179dfa64cc463eeca363006a30f5518747751420cfc1fb80c'}, 'src/org/trillionnium/hepta/local/ObservedChildText.java': {'bytes': 10858, 'sha256': '56433b62f9c4c895edac441160fcdc4aaee7365586daa4b86863448dc4dd54d5'}, 'src/org/trillionnium/hepta/local/ObservedTargetLabels.java': {'bytes': 4685, 'sha256': 'c4e1b1a7ae0223fc7cda90864c6a5c3759a2875bb435359464672bc79465c8ba'}, 'src/org/trillionnium/hepta/local/ObservationCaptureEvidence.java': {'bytes': 32347, 'sha256': 'e7306d40d576efda5541e139abfc7e07c794f538aee7522f8f1f466947935f4c'}, 'src/org/trillionnium/hepta/local/NativeCtripFormObservation.java': {'bytes': 25935, 'sha256': 'ff884b8cafe28330262e8ff27423eaf34553faed3556984a3d188876ccef02ad'}, 'src/org/trillionnium/hepta/local/NativeActionSnapshotCheck.java': {'bytes': 87473, 'sha256': '400db829f8b5942d9ad4a43a1bbbc18d96fe2138964482146b8cd08fd63ea593'}, 'src/org/trillionnium/hepta/local/ObservedScrollActions.java': {'bytes': 2303, 'sha256': 'c31012cf776fbc4177d6c617341d006f4a45ed63df3cfc435f705e515ebbc188'}, 'src/org/trillionnium/hepta/local/ObservedImeEnter.java': {'bytes': 4665, 'sha256': 'e449d61e928dca5a72730b5394fa8f95a7db4dd4006440a95f839818e165acf1'}, 'src/org/trillionnium/hepta/local/NativeXiaomiSearchInputObservation.java': {'bytes': 23824, 'sha256': 'ecf6a9ccf173dc78c6c167435dc745b4080aa85a4fb77b22c3d442b7674254c3'}, 'src/org/trillionnium/hepta/local/NativeXiaomiProductPage.java': {'bytes': 71093, 'sha256': '91fed98eafe2f3cbcc090d9a3f85085fa1feb0f3ba002d7b9a78c71b13569bf0'}, 'tests/native-xiaomi-product/NativeXiaomiProductPageHostTest.java': {'bytes': 41278, 'sha256': '325cae3ea203567e6c1c51b4c6d52948bc7f37ec6944a8e560bb3cdabe299b9c'}, 'tests/native-app-fixtures/NativeXmlFixture.java': {'bytes': 9971, 'sha256': '142e9a87d29e425c3284dc2b331709c0f3326e33004412e0bc8c2bbe6dca34d4'}, 'tests/native-xiaomi-search-input/NativeXiaomiSearchInputHostTest.java': {'bytes': 34653, 'sha256': '416ff522f52b14898d44e3986472b9a658216ded42008bf4d8275c20980419c3'}, 'tests/native-action-integration/NativeActionSnapshotCheckHostTest.java': {'bytes': 24467, 'sha256': 'c61991bb5074fe67f1fe443f24403413b2374e337f15c6669e52d5b9a7c42e7f'}, 'tests/native-ctrip-form-observation/FormPairHostTest.java': {'bytes': 17521, 'sha256': '9874629b7c95bdbeef2942712aab6974b8cb366e32690d149624d85d0cb7e757'}, 'tests/native-xiaomi-direct-card/DirectCardHostTest.java': {'bytes': 28817, 'sha256': '5d4fec0b295abe8a948f2c5ddc9fc9e09a5b24de5cb4b37eedc947fc74fcf8a5'}, 'tests/native-xiaomi-direct-card/direct-card-nodes.json': {'bytes': 71812, 'sha256': '1152948a35aabe9b72902805224e4b5a41c9bb65b44cd84ccdf43cfcbcce777a'}, 'tests/native-xiaomi-direct-card/PROVENANCE.json': {'bytes': 9293, 'sha256': '4fd43861701eef4dfa22845f63775d20932dea0774736e80c6eeb5d4e596565e'}, 'tests/native-xiaomi-direct-card/protected_direct_card.py': {'bytes': 14961, 'sha256': '13715c8b38ab6abf5ed2a913b9869370e5690e15eaf21360b8400e52af3ce65a'}, 'tests/native-xiaomi-search-input/real-censuses.json': {'bytes': 703748, 'sha256': 'a7680b4a53cc702c98da44439543984a933e67e0193e774df23ff07a8c569644'}, 'tests/native-xiaomi-product/fixtures/PROVENANCE.json': {'bytes': 8104, 'sha256': '86669e929c7fa99f86cc02206e06d0ec6fd4bd59aa5d02251c0277e67cb48d00'}, 'tests/native-xiaomi-product/fixtures/home.xml': {'bytes': 61712, 'sha256': 'c23ea3a29252a457f246b6cd6680a2b7a8c6fe974720ef6875331779196c3ed3'}, 'tests/native-xiaomi-product/fixtures/search-entry.xml': {'bytes': 60766, 'sha256': '390e9d5c8cf5c7baa89f318d6a48d0a87a33a71dbd6121e19628c71ea49a2e48'}, 'tests/native-xiaomi-product/fixtures/search-focus.xml': {'bytes': 60775, 'sha256': 'ca29a11ff87ef366612fddf5e8bd70248ffb0734b42ff68425578932a03c109b'}, 'tests/native-xiaomi-product/fixtures/suggestions.xml': {'bytes': 64964, 'sha256': '3f4c53a545c42dff04f4aeeaa990b695add1217cc0e468c1054de75c19005a26'}, 'tests/native-xiaomi-product/fixtures/results.xml': {'bytes': 55869, 'sha256': 'b19c4e8345f6c84db1d0debe7bc64e6257c05c65294ac2ad1d2f176a0b6baa56'}, 'tests/native-xiaomi-product/fixtures/detail.xml': {'bytes': 46256, 'sha256': 'cfcaac115754a654e9091336ba1ef8c7e43ba066191f5e80deeaa238b1b09f88'}, 'tests/native-xiaomi-product/fixtures/detail-readonly.xml': {'bytes': 46256, 'sha256': 'cfcaac115754a654e9091336ba1ef8c7e43ba066191f5e80deeaa238b1b09f88'}, 'tests/native-xiaomi-product/fixtures/search-history-overlap.xml': {'bytes': 62534, 'sha256': 'bb973b74d3dfe7ae66a5ef3a4a85a7c9048eca19f8b08be096753d965db28c0f'}, 'tests/native-xiaomi-product/fixtures/home-promotion.xml': {'bytes': 2610, 'sha256': '569a4cea3d1e6d30684f74fa33f3974bd861f337136959e4812a81318c288932'}, 'tests/native-xiaomi-product/fixtures/home-reset.xml': {'bytes': 61706, 'sha256': '5fb9e9f40d4efbc6e10571281db217f5ffe05043c22b9824fe3c51330074869e'}}
ACTUAL_PINS={'owner.json': {'bytes': 10542, 'sha256': '7a2465d488e45e4ba6851c93bb35e9868d2f1eee9be1e84bc7f06e2e7616c1b3'}, 'native-app-page-0003.json': {'bytes': 337097, 'sha256': '4af2580bc868472215dd74124d36bf25100d5682f0f61f5ce482a02600a272c4'}, 'step-03-after.json': {'bytes': 85469, 'sha256': '95a276dd5dd01df6016da8e6f24c7281784b668fe27b8fd4e0ee2944f27383c5'}, '572304edf78a4ba89228579022176658-native-ax.json': {'bytes': 100102, 'sha256': '3307b70efd29c46762c3f5e3cb7be9e973f105d54e3d754f55821bbd3412f525'}}
def sha(raw):return hashlib.sha256(raw).hexdigest()
def need(ok,why):
    if not ok:raise RuntimeError(why)
def info(p):
    s=p.lstat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1,"regular immutable input: "+str(p))
    raw=p.read_bytes();e=p.lstat()
    need((s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)==(e.st_dev,e.st_ino,e.st_size,e.st_mtime_ns),"input changed while reading")
    return {"path":str(p),"bytes":len(raw),"sha256":sha(raw),"mode":stat.S_IMODE(e.st_mode)}
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("source","output","java-home","json-jar"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--actual-task",type=Path)
    a=p.parse_args()
    need(all(x.is_absolute() for x in [a.source,a.output,a.java_home,a.json_jar]+([a.actual_task] if a.actual_task else [])),"absolute paths")
    need(not a.output.exists() and a.source not in a.output.parents,"fresh output outside source")
    originals={}
    history_helper=a.source/"tests/native-xiaomi-search-history/protected_history_prefix.py"
    history_meta=info(history_helper)
    need(history_meta["sha256"]=="90c3fbb3550ee110dd9f939aecf65ebad210694fa128e9371f7076c6d2ad08d5","exact reviewed history inverse helper")
    originals[str(history_helper)]=history_meta
    history_predecessor=runpy.run_path(str(history_helper))["predecessor"]
    detail_helper=a.source/"tests/native-xiaomi-detail-mirror/protected_detail_mirror.py"
    detail_meta=info(detail_helper)
    need(detail_meta["sha256"]=="f1bf83564946293cc0074b64dfe5b5ae858d3115d3299005ea9296548dae143a","exact reviewed detail inverse helper")
    originals[str(detail_helper)]=detail_meta
    detail_predecessor=runpy.run_path(str(detail_helper))["predecessor"]
    for rel,pin in PIN_DATA.items():
        meta=info(a.source/rel)
        proof_raw=history_predecessor((a.source/rel).read_bytes()) if rel==PKG+"NativeXiaomiSearchInputObservation.java" else None
        if rel==PKG+"NativeXiaomiProductPage.java":proof_raw=detail_predecessor((a.source/rel).read_bytes())
        need((len(proof_raw)==pin["bytes"] and sha(proof_raw)==pin["sha256"]) if proof_raw is not None
             else (meta["bytes"]==pin["bytes"] and meta["sha256"]==pin["sha256"]),"exact source/fixture predecessor pin: "+rel)
        originals[str(a.source/rel)]=meta
    originals[str(Path(__file__).resolve())]=info(Path(__file__).resolve())
    jar=info(a.json_jar);need(jar["bytes"]==78332 and jar["sha256"]==JSON_SHA,"JSON dependency pin")
    originals[str(a.json_jar)]=jar
    if a.actual_task:
        for name,pin in ACTUAL_PINS.items():
            meta=info(a.actual_task/name);need(meta["bytes"]==pin["bytes"] and meta["sha256"]==pin["sha256"],"exact actual archive: "+name)
            originals[str(a.actual_task/name)]=meta
    a.output.mkdir(mode=0o755,parents=True);classes=a.output/"classes";classes.mkdir()
    result={"schema":"hepta.xiaomi-direct-card-compiled-gate.v1","all_pass":False,"steps":[],"phone_operations":0,
        "android_runtime":False,"dispatch_executed":False,"business_completion_verified":False,
        "actual_replay_requested":bool(a.actual_task),"started_epoch":time.time()}
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1")
    for key in ("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","CLASSPATH"):env.pop(key,None)
    def command(name,argv,expected_failure=None):
        began=time.monotonic();r=subprocess.run([str(x) for x in argv],cwd=a.source,env=env,capture_output=True,timeout=90)
        (a.output/(name+".stdout")).write_bytes(r.stdout);(a.output/(name+".stderr")).write_bytes(r.stderr)
        entry={"name":name,"argv":[str(x) for x in argv],"exit_code":r.returncode,"seconds":time.monotonic()-began,
            "stdout_bytes":len(r.stdout),"stdout_sha256":sha(r.stdout),"stderr_bytes":len(r.stderr),"stderr_sha256":sha(r.stderr)}
        result["steps"].append(entry)
        if expected_failure:
            need(r.returncode!=0 and expected_failure.encode() in r.stderr,"baseline must reject exact positive without this fix")
            entry["expected_failure"]=True;entry["failure_marker"]=expected_failure
        else:
            if r.returncode:print(r.stdout.decode(errors="replace")[-6000:]);print(r.stderr.decode(errors="replace")[-6000:])
            need(r.returncode==0,"actual host command failed: "+name)
    try:
        helper=runpy.run_path(str(a.source/TEST/"protected_direct_card.py"))
        base_inverse=helper["predecessor"]
        def inverse(name,raw):
            if name=="NativeXiaomiProductPage.java" and sha(raw)!=helper["PINS"][name]["before_sha256"]:
                raw=detail_predecessor(raw)
            return base_inverse(name,raw)
        cases=[]
        for name in ("ObservationCaptureEvidence.java","NativeXiaomiProductPage.java"):
            raw=(a.source/PKG/name).read_bytes();prior=inverse(name,raw)
            need(inverse(name,prior)==prior,"exact prior identity path")
            cases.extend([{"name":name+":current_exact","passed":True},{"name":name+":prior_exact","passed":True}])
            for label,changed in (("appended",raw+b"\n"),("truncated",raw[:-1]),("prefix",b" "+raw),("prior_appended",prior+b"\n"),("body_changed",raw.replace(b"return",b"throw ",1))):
                failed=False
                try:inverse(name,changed)
                except (ValueError,AssertionError):failed=True
                need(failed,"unknown source must refuse: "+label);cases.append({"name":name+":"+label,"passed":True})
        result["strict_inverse_cases"]={"all_pass":True,"cases":len(cases),"results":cases}
        compile_rels=[k for k in PIN_DATA if k.endswith(".java")]
        args=[a.java_home/"bin/javac","--release","8","-encoding","UTF-8","-proc:none","-Xlint:all","-Werror","-cp",a.json_jar]
        command("compile",args+["-d",classes]+[a.source/x for x in compile_rels])
        fixture=a.source/TEST/"direct-card-nodes.json";history=a.source/"tests/native-xiaomi-search-input/real-censuses.json"
        argv=[a.java_home/"bin/java","-cp",str(classes)+os.pathsep+str(a.json_jar),"org.trillionnium.hepta.local.DirectCardHostTest",fixture,history,a.output]
        if a.actual_task:argv.append(a.actual_task)
        command("direct_cases",argv)
        cases=json.loads((a.output/"CASES.json").read_bytes());need(cases["all_pass"] is True and len(cases["results"])==cases["cases"],"complete actual direct-card cases")
        names=[x["name"] for x in cases["results"]];need(len(names)==len(set(names)) and all(x["passed"] is True for x in cases["results"]),"case identity")
        for required in ("public_actual_70_node_51_projection_shape","hidden_unretained_extra_number","retained_app_tree_signature_mismatch",
                         "sealed_census_is_deeply_immutable","form_history_cannot_supply_ordinary_census","input_history_cannot_supply_ordinary_census"):
            need(required in names,"required exact matrix case "+required)
        result["direct_cases"]=cases
        if a.actual_task:
            actual=json.loads((a.output/"ACTUAL-REPLAY.json").read_bytes());need(actual["all_pass"] and actual["original_node_count"]==70 and actual["retained_node_count"]==51,"exact actual replay")
            result["actual_replay"]=actual
        command("legacy_75",[a.java_home/"bin/java","-cp",str(classes)+os.pathsep+str(a.json_jar),
            "org.trillionnium.hepta.local.NativeXiaomiProductPageHostTest",a.source/"tests/native-xiaomi-product/fixtures",a.output/"LEGACY-75.json"])
        old=json.loads((a.output/"LEGACY-75.json").read_bytes());need(old["all_pass"] is True and old["cases"]==75,"unchanged original 75 cases")
        result["legacy_75"]=old
        baseline=a.output/"baseline-source"/"NativeXiaomiProductPage.java";baseline.parent.mkdir()
        baseline.write_bytes(inverse("NativeXiaomiProductPage.java",(a.source/PKG/"NativeXiaomiProductPage.java").read_bytes()))
        baseline_classes=a.output/"baseline-classes";baseline_classes.mkdir()
        command("compile_baseline",args+["-d",baseline_classes]+[baseline if x==PKG+"NativeXiaomiProductPage.java" else a.source/x for x in compile_rels])
        baseline_output=a.output/"baseline-output";baseline_output.mkdir()
        if a.actual_task:
            command("baseline_actual_red",[a.java_home/"bin/java","-cp",str(baseline_classes)+os.pathsep+str(a.json_jar),
                "org.trillionnium.hepta.local.DirectCardHostTest","--actual-only",a.actual_task,baseline_output],
                expected_failure="private original direct card must quote")
            result["baseline_red"]={"all_pass":True,"input":"exact_original_70_raw_51_retained","parser_sha256":sha(baseline.read_bytes())}
        else:
            command("baseline_public_red",[a.java_home/"bin/java","-cp",str(baseline_classes)+os.pathsep+str(a.json_jar),
                "org.trillionnium.hepta.local.DirectCardHostTest",fixture,history,baseline_output],
                expected_failure="actual direct-child card must quote")
            result["baseline_red"]={"all_pass":True,"input":"public_derived_shape_synthetic_binding","parser_sha256":sha(baseline.read_bytes())}
        result["all_pass"]=True
    except Exception as error:
        result["error"]=type(error).__name__+": "+str(error);(a.output/"ERROR.txt").write_text(traceback.format_exc())
    finally:
        result["inputs_unchanged"]=all(info(Path(path))==value for path,value in originals.items())
        result["all_pass"]=result["all_pass"] and result["inputs_unchanged"];result["source_inputs"]=list(originals.values());result["finished_epoch"]=time.time()
        out=(json.dumps(result,ensure_ascii=False,indent=2)+"\n").encode();(a.output/"RESULT.json").write_bytes(out)
        for q in a.output.rglob("*"):
            if q.is_file():q.chmod(0o644)
        print(json.dumps({"all_pass":result["all_pass"],"error":result.get("error"),"direct_cases":result.get("direct_cases",{}).get("cases"),
            "legacy_cases":result.get("legacy_75",{}).get("cases"),"actual_replay":bool(result.get("actual_replay")),
            "result":str(a.output/"RESULT.json"),"bytes":len(out),"sha256":sha(out)},ensure_ascii=False))
    return 0 if result["all_pass"] else 1
if __name__=="__main__":raise SystemExit(main())
