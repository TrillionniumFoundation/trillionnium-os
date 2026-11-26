#!/usr/bin/env python3
"""Actual private history admission and explicitly synthetic current-proof/consumer tests. No phone."""
import argparse,hashlib,json,os,stat,subprocess,traceback
from pathlib import Path
JSON_SHA="941cc2fe5b1e42c30ceeeb25578e589a137094d5eccf84d67196eca9c29e5cdb"
MAIN="org.trillionnium.hepta.local.NotesWorkflowReleasedReplyLostHostTest"
def need(v,m):
    if not v:raise RuntimeError(m)
def raw(p):
    p=Path(p);a=p.lstat();need(p.is_absolute() and p.resolve()==p and stat.S_ISREG(a.st_mode) and a.st_nlink==1,"regular unaliased input required: "+str(p))
    b=p.read_bytes();z=p.lstat();need((a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns) and len(b)==a.st_size,"changed input")
    return b
def ref(p):
    p=Path(p);b=raw(p);return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def put(p,v):
    b=v if isinstance(v,bytes) else (json.dumps(v,ensure_ascii=False,indent=2)+"\n").encode()
    with Path(p).open("xb") as f:f.write(b)
    os.chmod(p,0o600)
def mapped(p):
    m=json.loads(raw(p));need(m["schema"]=="hepta.actual-private-original-input-map.v1" and len(m["rows"])==24,"exact 23 originals plus current control required")
    result={}
    for r in m["rows"]:
        need(r["role"] not in result,"duplicate role");v=ref(r["host_path"]);need((v["bytes"],v["sha256"])==(r["bytes"],r["sha256"]),"original changed");result[r["role"]]=v
    return result
def approved_aborted_client_predecessor(current,previous):
    """Prove this exact v13 Client delta; compilation still uses the current full client classes."""
    need(hashlib.sha256(current).hexdigest()=="d80c2e7c725980b07e5ae6f2a425f5f914cc8c3db7a4c5d8dc6ec55a009df0de",
         "unreviewed current Notes recovery client")
    need(hashlib.sha256(previous).hexdigest()=="2d8db023a62b3c8f1410bacf0b3af0f2632cb474714020badac79963052bab5d",
         "unexpected v12 consumer predecessor")
    edits=[(32, 33, 32, 34, 'c2ed4aa0463902817e140b74aacf799bfb464bdd7f4e265f1c576e0d0e2d29b0', 'ec459a71c371b85a3e5d4f4abf2ce110cedd0c01f2f48d554459b12f8f9b5219'), (38, 40, 39, 44, '08865d48148bece6930a337f447474419dae79fb7db5fd167458ad9d9f1d7edc', '46eda3a8ea86de7ad66e040dc01bd792421d3a0db906986ef960cc883b3013a1'), (46, 46, 50, 51, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'de070e8d2a0f4e34844d5d0d095fd7c5bffe8401a71541c9421abf15d344f81f'), (47, 48, 52, 53, '4ce2c8030af49493c8221ee29b1e11d9d501916a0381ce54af47a0eda245ddbf', '21472d4756cb2df43ac3fb9b6a459a04a2537109840f994c7683b837541b91c7'), (63, 63, 68, 69, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', '67e24c7cdb368c270bccf8598122d22647eb7d5f6b236ae4babb1c414b41f421'), (85, 85, 91, 97, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', '7fe98c5af07ae5cdeea6ae39ad07b3df9a7fe86e4645c87695919e072debc51e'), (101, 101, 113, 114, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'eae8699c681f82a44fff89e15dad5ab6525ec554795982256763ea7504123e6f'), (143, 143, 156, 158, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', '191302b8f88acb3db9acd80796ecd5bc2de4f6722bf7dfa12bd3408a447fcee9'), (151, 152, 166, 168, 'a4e01681d44487ec06dbceb58869d9a7c38b6b0e0ad21810919b228064dd0a3c', 'd4d3ef842754b548acfd87f912cd01c7356bf4788a4b287cf74738d7f929aa82'), (162, 163, 178, 179, '15da8d2bfe64bac437464138b8a8508137d174c1992023ae47b6c9e7a2b51b0e', '2b646a4a64629a558fdf11904bb52667cb6c88554682551f4f84dd167d0d671a'), (175, 175, 191, 195, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'efec81eb80c9bfddbde19a09e5d94ebe8482455eed60c9bc40d0e1c366996cdc'), (180, 180, 200, 201, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'f4b3d8ca0efca4456ebd64b631c643275827bb89ee85b09edd1a3f911b84abcd'), (183, 184, 204, 205, 'dd8731f0f77f18bfff96e869e8e8b0a36a57ae298888c12de18ea0860eb927a8', '8fffdc5b54002389b480ac6b9186039180e662645d0f7e8dcbd7e4c5dbdacc8e'), (195, 196, 216, 217, 'b90d4be5d3b50781fd1a0ecccb01dddbb2cfed544e81b08c521d81efdfef8f58', '00ba54eeec52f93bc8c902cd604c99984ca732cb83070ca8e1e7c588e49d8094'), (302, 302, 323, 324, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'af909441f74fa19751a9279f9eb5cab2b727e9132d20b7b3a34db8a1f488b28e'), (334, 334, 356, 408, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', '53c297bb4f8d28d4c308bb51aa69cdb85a1c5599fdd2c9d3811d1882c20cf088')]
    a=previous.splitlines(keepends=True);b=current.splitlines(keepends=True);restored=list(b)
    for a0,a1,b0,b1,old_sha,new_sha in reversed(edits):
        before=b"".join(a[a0:a1]);after=b"".join(b[b0:b1])
        need(hashlib.sha256(before).hexdigest()==old_sha and hashlib.sha256(after).hexdigest()==new_sha,
             "exact v13 client inverse span differs")
        restored[b0:b1]=a[a0:a1]
    need(b"".join(restored)==previous,"complete v12 client predecessor inverse differs")
    return dict(current_sha256=hashlib.sha256(current).hexdigest(),
                predecessor_sha256=hashlib.sha256(previous).hexdigest(),
                full_source_inverse_equal=True,known_edit_count=len(edits),
                historical_client_class_substituted=False)
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ("source","base-source","output","java-home","android-json-jar","dependency-classes","private-input-map","legacy-input-map"):p.add_argument("--"+n,required=True)
    a=p.parse_args();source=Path(a.source);base=Path(a.base_source);out=Path(a.output);jdk=Path(a.java_home);jar=Path(a.android_json_jar);deps=Path(a.dependency_classes);mapping=Path(a.private_input_map);legacy=Path(a.legacy_input_map)
    for v in (source,base,out,jdk,jar,deps,mapping,legacy):need(v.is_absolute() and v.resolve()==v,"absolute unaliased path required")
    need(not out.exists() and source.is_dir() and base.is_dir() and deps.is_dir(),"new output/existing source required")
    need(ref(jar)["sha256"]==JSON_SHA,"actual Android16 JSON implementation required")
    before=mapped(mapping);old=mapped(legacy)
    rel="src/org/trillionnium/hepta/background/PublicPersonalNotesAbsenceRecovery.java"
    test=source/"tests/notes-workflow-released-reply-lost/NotesWorkflowReleasedReplyLostHostTest.java"
    oldtest=source/"tests/notes-workflow-foreign-history/NotesWorkflowForeignHistoryHostTest.java"
    sources=[ref(source/rel),ref(base/rel),ref(test),ref(oldtest)]
    consumers=["PublicPersonalNotesRecoveryClient.java","BackgroundSession.java","MobiMindPrivateFiles.java","RecoveryJournalTransaction.java","RecoveryQuiescence.java","SessionRecovery.java","LocalTaskSession.java"]
    client_predecessor=None
    for name in consumers:
        r="src/org/trillionnium/hepta/local/"+name
        current,previous=raw(source/r),raw(base/r)
        if name=="PublicPersonalNotesRecoveryClient.java" and current!=previous:
            client_predecessor=approved_aborted_client_predecessor(current,previous)
            sources.append(ref(base/r))
        else:need(current==previous,"unchanged consumer source required: "+r)
        sources.append(ref(source/r))
    for name in ("WorkerGenerationProof.java",):
        r="src/org/trillionnium/hepta/local/"+name
        need(raw(source/r)==raw(base/r),"unchanged generation source required");sources.append(ref(source/r))
    for name in ("PublicPersonalNotesAbsenceMain.java","PublicPersonalNotesHistory.java"):
        r="src/org/trillionnium/hepta/background/"+name
        need(raw(source/r)==raw(base/r),"unchanged absence producer required");sources.append(ref(source/r))
    dep_refs=[ref(x) for x in sorted(deps.rglob("*.class"))];need(dep_refs,"complete compiled dependency inventory required")
    out.mkdir(mode=0o700,parents=True);env=dict(os.environ)
    for k in ("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","CLASSPATH"):env.pop(k,None)
    report=dict(schema="hepta.notes-workflow-released-reply-lost-runner.v1",all_pass=False,source_root=str(source),base_source_root=str(base),
      sources=sources,private_input_map=ref(mapping),private_originals=before,legacy_input_map=ref(legacy),legacy_originals=old,
      android_json_jar=ref(jar),java=ref(jdk/"bin/java"),javac=ref(jdk/"bin/javac"),
      dependency_classes=str(deps),dependency_class_refs=dep_refs,stages=[],phone_operations=0,current_absence_proven=False,
      app_recovery_completed=False,business_success_claimed=False,
      current_client_source_predecessor=client_predecessor)
    def run(label,argv):
        put(out/(label+".argv.json"),argv)
        c=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,env=env,timeout=180)
        put(out/(label+".stdout"),c.stdout);put(out/(label+".stderr"),c.stderr)
        r=dict(label=label,argv=argv,exit_code=c.returncode,stdout=ref(out/(label+".stdout")),stderr=ref(out/(label+".stderr")))
        report["stages"].append(r);need(c.returncode==0 and c.stderr==b"","stage failed: "+label);return c.stdout
    try:
        for kind,s in (("baseline",base),("candidate",source)):
            classes=out/(kind+"-classes");classes.mkdir(mode=0o700)
            files=[s/rel,test]+([oldtest] if kind=="candidate" else [])
            cp=os.pathsep.join(map(str,(jar,deps)));runtime=os.pathsep.join(map(str,(classes,jar,deps)))
            run(kind+"-compile",[str(jdk/"bin/javac"),"--release","8","-Xlint:all,-options","-Werror","-encoding","UTF-8","-proc:none","-cp",cp,"-d",str(classes)]+list(map(str,files)))
            result=json.loads(run(kind+"-test",[str(jdk/"bin/java"),"-Dhepta.android.json.path="+str(jar),"-cp",runtime,MAIN,str(mapping),str(out/(kind+"-scratch")),kind]))
            need(result["all_pass"] and result["mode"]==kind and result["phone_operations"]==0 and result["current_absence_proven"] is False,"closed report")
            report[kind+"_summary"]=result
            if kind=="candidate":
                for field in ("request_roundtrip_exact","normal_model_generation_validator_passed","client_and_background_dynamic_source_passed","actual_ack_new_idle_consumer_passed","original_byte_preservation"):need(result[field] is True,"consumer failed "+field)
                oldresult=json.loads(run("legacy-v11-test",[str(jdk/"bin/java"),"-cp",runtime,"org.trillionnium.hepta.local.NotesWorkflowForeignHistoryHostTest",str(legacy),str(out/"legacy-v11-scratch")]))
                need(oldresult["all_pass"] and oldresult["cases"]==203 and oldresult["assertions"]==339 and oldresult["phone_operations"]==0,"old v11 regression failed")
                report["legacy_v11_summary"]=oldresult
            report[kind+"_compiled_classes"]=[ref(x) for x in sorted(classes.rglob("*.class"))]
        need(before==mapped(mapping) and old==mapped(legacy),"private original changed")
        need(sources==[ref(x["path"]) for x in sources],"source changed")
        need(dep_refs==[ref(x) for x in sorted(deps.rglob("*.class"))],"compiled dependency changed")
        report["all_pass"]=True;report["all_original_bytes_unchanged"]=True
    except Exception as e:
        report["error"]=str(e);report["traceback"]=traceback.format_exc()
    put(out/"RESULT.json",report)
    print(json.dumps(dict(all_pass=report["all_pass"],result=ref(out/"RESULT.json"),baseline=report.get("baseline_summary",{}).get("cases"),
      candidate=report.get("candidate_summary",{}).get("cases"),legacy_v11=report.get("legacy_v11_summary",{}).get("cases"),phone_operations=0)))
    return 0 if report["all_pass"] else 1
if __name__=="__main__":raise SystemExit(main())
