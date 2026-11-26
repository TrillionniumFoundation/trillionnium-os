#!/usr/bin/env python3
"""Exact live profile identity RPC and independent terminal verification boundaries."""
import argparse, hashlib, importlib.util, json, os, stat, subprocess, sys, time
from pathlib import Path
sys.dont_write_bytecode=True
BASE_CONFIG="cdd7d37884bfe48e2ba2e4b73d20def23d1ed76d86bbcba40c1dc4f16db8e23a"
CURRENT_CONFIG="a8ae6cecc14b7347871e13b32cc73df88955bfc77266a47191e1806ff3ec3d96"
BASE_CONTROLLER="2651cdc0497a7bf6690825ab0d94fcff10232d1ed783246b30fc97f00dc49277"
UNCHANGED={
 "src/org/trillionnium/hepta/local/BackgroundSession.java":"8109ceb4acc2d2c8577bc5fc5e8d37ce259117100e42b846a601a371f1641eb1",
 "src/org/trillionnium/hepta/background/BackgroundDisplayBroker.java":"a74cd6c88a4468631c8e3d2f70fab7e1a6e7d66a6749cfc0c98742456a3f6f44",
 "src/org/trillionnium/hepta/background/ProfilePackages.java":"45ba900bb29b4efc12e7fef732e7d68c9594929c17ae67855f600cb5ee4e0630",
 "src/org/trillionnium/hepta/background/ProfileTarget.java":"268dc50e7d3205cc8fb35883843fbdf8a10cc517f773867a9aae6d00fe07f2fd",
 "src/org/trillionnium/hepta/local/ProfileCatalogueClient.java":"bd6629fe5fc14b656a7afc8b8e8af43260c5b57d5c4180200cf80b90b7b04d6f",
 "src/org/trillionnium/hepta/background/ProfileCatalogueMain.java":"1fea96b41e8a63372f599fc7f54607e37d9c3bb793ec378e3bcac25abc5cc665",
 "src/org/trillionnium/hepta/local/NativeCalendarDateEnvelope.java":"63e5063098878551248b630e2daba46ab7efd556f806963e85450238b186d734"}
EXPECTED=[
 "ctrip_each_live_call_uses_original_state_rpc","xiaomi_each_live_call_uses_same_profile_channel",
 "identity_holds_exact_captured_session_object","target_only_identity_cannot_use_live_path",
 "constructor_rejects_different_captured_target","released_session_refuses_without_catalogue_fallback",
 "expired_session_refuses_before_transport","equal_target_new_session_cannot_replace_original_closed_session",
 "missing_socket_refuses_without_catalogue_fallback","unauthorized_peer_refuses_before_request_bytes","public_scope_shell_peer_refuses_before_request_bytes",
 "unverified_profile_identity_refuses","wrong_request_id_refuses","wrong_generation_refuses",
 "wrong_virtual_display_refuses","physical_display_refuses","released_during_live_rpc_refuses",
 "rpc_failure_refuses","expiry_during_live_rpc_refuses",
 *["changed_"+key+"_refuses" for key in ("serial","uid","version","apk","split","signer","component","package")],
 "terminal_verify_after_release_uses_original_catalogue_only",
 "terminal_verify_has_no_live_fallback_when_catalogue_unavailable"]
# Reviewed cleanup evolution is reversed only for historical source proofs.
# Actual compiler paths and method extraction always use current production.
def _cleanup_phase_inputs():
    source = Path(__file__).resolve().parents[2]
    return [source / "tests/profile-cleanup-settle/protected_cleanup_phase.py",
            source / "tests/profile-cleanup-settle/production-predecessor.json"]

def _cleanup_phase_proof(relative, raw):
    from runpy import run_path
    helper = _cleanup_phase_inputs()[0]
    if hashlib.sha256(helper.read_bytes()).hexdigest() != "a48c11798f672654823b2cf6dd9f19d31d7ea1a20f1d69b488eb1a4e4019a8d2":
        raise RuntimeError("fixed cleanup proof helper differs")
    return run_path(str(helper))["predecessor"](relative, raw)

def sha(raw): return hashlib.sha256(raw).hexdigest()
def record(path):
 p=Path(path).resolve();raw=p.read_bytes()
 return dict(path=str(p),bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE(p.stat().st_mode))
def module(path,name):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def require(value,reason):
 if not value: raise RuntimeError(reason)
def once(raw,old,new):
 require(raw.count(old)==1,"exact unique source fragment required: "+old[:100])
 return raw.replace(old,new,1)
def admitted_close_proof_copy(text):
 text=_cleanup_phase_proof("src/org/trillionnium/hepta/background/BackgroundDisplayBroker.java",text.encode()).decode()
 # This copy proves only the exact two-line authenticated Notes-close change.
 # All actual producer refs and compiled sources remain the current source.
 if sha(text.encode())=="abccc17b66df24056a75bb44d8b0f9c6c790727cf0ac2abd4067a0d27d60ea7c":
  text=once(text,
   "    // Only an authenticated, already admitted profile or personal Notes close RPC owns this peer.\n",
   "    // Only the authenticated, already admitted work-profile close RPC can own this peer.\n")
  text=once(text,
   '                        if(config.publicOwnGroupScope!=null&&(config.profileTarget!=null||publicNotesCustody!=null)&&"close".equals(request.operation))\n',
   '                        if(config.publicOwnGroupScope!=null&&config.profileTarget!=null&&"close".equals(request.operation))\n')
  require(sha(text.encode())=="a74cd6c88a4468631c8e3d2f70fab7e1a6e7d66a6749cfc0c98742456a3f6f44",
   "exact authenticated Notes close inverse must restore the entire profile identity producer")
 return text
def source_contract(source,output):
 config_path=source/"src/org/trillionnium/hepta/local/QualificationScopeConfig.java"
 controller_path=source/"src/org/trillionnium/hepta/local/LocalTaskController.java"
 config=config_path.read_text();controller=controller_path.read_text()
 require(sha(config.encode())==CURRENT_CONFIG,"reviewed full installed identity source required")
 verify='        void verify(Context context)throws Exception{if(profileTarget==null)installed.verify(context);else ProfileCatalogueClient.requireCurrent(context,profileTarget);}\n'
 require(config.count(verify)==1,"original independent terminal verify must remain exact")
 proof=config
 proof=once(proof,"        private final BackgroundSession profileSession;\n","")
 proof=once(proof,"installed=value;profileTarget=null;profileSession=null;","installed=value;profileTarget=null;")
 proof=once(proof,'''        private CompletionInstalledIdentity(org.trillionnium.hepta.background.ProfileTarget target){
            this(target,null);
        }
        private CompletionInstalledIdentity(org.trillionnium.hepta.background.ProfileTarget target,BackgroundSession session){
            installed=null;profileTarget=target;profileSession=session;packageName=target.packageName;uid=target.fullUid;
            versionCode=target.versionCode;apkHashes=target.apkHashes;
            QualificationScope.require(session==null||target.same(session.profileTarget()),"captured profile session target differs");
        }
''','''        private CompletionInstalledIdentity(org.trillionnium.hepta.background.ProfileTarget target){
            installed=null;profileTarget=target;packageName=target.packageName;uid=target.fullUid;
            versionCode=target.versionCode;apkHashes=target.apkHashes;
        }
''')
 proof=once(proof,"return new CompletionInstalledIdentity(target,background);","return new CompletionInstalledIdentity(target);")
 extension='''        /** Active-task checks use the exact captured broker, never a cached success.
         * Its original RPC re-reads target-user PM/profile state and the complete
         * APK identity. The independent post-cleanup verify above remains separate. */
        void verifyLive(Context context)throws Exception{
            if(profileTarget==null){installed.verify(context);return;}
            QualificationScope.require(profileSession!=null&&profileTarget.same(profileSession.profileTarget()),
                    "same captured live profile session required");
            profileSession.verifyProfileInstallation();
            QualificationScope.require(profileTarget.same(profileSession.profileTarget()),"live profile session target changed");
        }
'''
 proof=once(proof,extension,"");require(sha(proof.encode())==BASE_CONFIG,"all original installed identity bytes required")
 callback="new NativeAppSession.InstalledVerifier(){public void verify()throws Exception{nativeInstalled.verifyLive(service);}}"
 after='if(completionInstalled!=null)try{completionInstalled.verifyLive(service);}catch(Exception changed){completion.invalidateInstalled("installed_notes_identity_changed");}'
 terminal='if(completionInstalled!=null)try{completionInstalled.verify(service);nativeInstalledRechecked=completion.nativeGoal()!=null;}catch(Exception changed){'
 require(controller.count(callback)==1 and controller.count(after)==1 and controller.count(terminal)==1,"exact live and independent terminal callsites required")
 cp=once(controller,callback,callback.replace("verifyLive","verify"))
 cp=once(cp,after,after.replace("verifyLive","verify"))
 # The sibling Xiaomi patch changes these two UI explanations only. Both
 # reviewed source states must restore the entire actual 1fab Controller.
 ui_pairs=[
  ('if(++staleRounds>2)throw new IllegalStateException("页面或控件校验连续未通过，已停止操作以免点错目标");',
   'if(++staleRounds>2)throw new IllegalStateException("画面连续变化，已停止操作以免点错目标");'),
  ('emit("页面或控件校验未通过，正在重新观察…");','emit("画面发生变化，正在重新观察…");')]
 ui=all(cp.count(new)==1 for new,old in ui_pairs)
 if ui:
  for new,old in ui_pairs: cp=once(cp,new,old)
 require(sha(cp.encode())==BASE_CONTROLLER,"Controller may differ only by two live callsites and exact sibling UI explanations")
 checks=[];close_proofs=[]
 for rel,digest in UNCHANGED.items():
  row=record(source/rel)
  if rel=="src/org/trillionnium/hepta/background/BackgroundDisplayBroker.java" and row["sha256"]!=digest:
   broker_proof=admitted_close_proof_copy((source/rel).read_text())
   require(sha(broker_proof.encode())==digest,"exact authenticated close producer inverse differs")
   close_proofs.append(dict(actual_source=row,original_whole_sha256=digest,proof_copy_only=True))
  else:
   require(row["sha256"]==digest,"unchanged full identity/freshness producer differs: "+rel);checks.append(row)
 bridge=output/"LiveIdentityControllerBridge.java"
 bridge.write_text("package org.trillionnium.hepta.local;\nfinal class LiveIdentityControllerBridge {\n"
  +"static NativeAppSession.InstalledVerifier verifier(QualificationScopeConfig.CompletionInstalledIdentity nativeInstalled,android.content.Context service){return "+callback+";}\n"
  +"static void after(QualificationScopeConfig.CompletionInstalledIdentity completionInstalled,android.content.Context service,TaskCompletionGate completion){"+after+"}\n}\n")
 return bridge,dict(original_verify_preserved=True,whole_config_inverse_sha256=sha(proof.encode()),
  whole_controller_inverse_sha256=sha(cp.encode()),sibling_ui_explanation_patch=ui,live_callback_sha256=sha(callback.encode()),
  live_after_action_sha256=sha(after.encode()),terminal_callsite_sha256=sha(terminal.encode()),
  actual_compiled_controller_bridge=record(bridge),unchanged_exact_producers=checks,authenticated_close_inverse_proofs=close_proofs,
  freshness_ms=2000,live_state_rpc_budget_ms=1800,installed_verification_calls_removed=0,
  cached_success_added=False,root_process_or_phone_executed=False)
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for key in ("source","output","java-home","json-jar"):p.add_argument("--"+key,required=True,type=Path)
 a=p.parse_args();source=a.source.resolve();out=a.output.resolve();jdk=a.java_home.resolve();jar=a.json_jar.resolve()
 require(not out.exists() and source not in out.parents,"fresh independent output required")
 out.mkdir(parents=True,mode=0o700)
 closure_path=source/"tests/native-search-planning/host_closure.py";closure=module(closure_path,"live_profile_actual_closure")
 require(sha(jar.read_bytes())==closure.JSON_SHA,"pinned actual org.json jar required")
 test=source/"tests/native-profile-live-identity/LiveProfileIdentityHostTest.java"
 calendar_test=source/"tests/native-calendar-date-protocol/NativeCalendarDateProtocolHostTest.java"
 bridge,contract=source_contract(source,out)
 paths,provenance=closure.prepare(source,out/"closure",(test,calendar_test,bridge))
 extra=[source/"src/org/trillionnium/hepta/local/VlmPins.java"]
 paths=list(dict.fromkeys(paths+extra))
 originals=list(dict.fromkeys([Path(r["path"]) for r in provenance["production_inputs"]]+extra+[Path(__file__).resolve(),source/"src/org/trillionnium/hepta/local/LocalTaskController.java"]+[source/x for x in UNCHANGED]))
 originals += _cleanup_phase_inputs()
 tools=[jdk/"bin/java",jdk/"bin/javac",jdk/"lib/modules",jar,Path(sys.executable).resolve()]
 before=[record(x) for x in originals];tool_before=[record(x) for x in tools]
 report=dict(schema="hepta.native-profile-live-identity-gate.v1",all_pass=False,source=str(source),source_inputs_before=before,
  tools_before=tool_before,closure=provenance,source_contract=contract,compile_inputs=[record(x) for x in paths],
  stages=[],phone_actions=0,model_runs=0,device_latency_measured=False,business_verified=False,
  boundary="Exact complete production CompletionInstalledIdentity, full BackgroundSession and NativeAppSession. Two actual Controller callsite extracts. Existing Android socket/display/clock and terminal PM catalogue host IO; no real broker process or phone claim.")
 classes=out/"classes";classes.mkdir();env=dict(os.environ);env["PATH"]=str(jdk/"bin")+":/usr/bin:/bin";env["PYTHONDONTWRITEBYTECODE"]="1"
 for key in ("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","CLASSPATH"):env.pop(key,None)
 calendar=out/"calendar";calendar.mkdir()
 commands=[
 ("compile",[jdk/"bin/javac","--release","8","-encoding","UTF-8","-proc:none","-Xlint:all,-options","-Werror","-cp",jar,"-d",classes,*paths]),
 ("live-identity",[jdk/"bin/java","-cp",str(classes)+os.pathsep+str(jar),"org.trillionnium.hepta.local.LiveProfileIdentityHostTest",out/"LIVE-CASES.json",out/"live-work"]),
 ("original-profile",[jdk/"bin/java","-cp",str(classes)+os.pathsep+str(jar),"org.trillionnium.hepta.local.NativeProfileIdentityHostTest",out/"ORIGINAL-PROFILE-CASES.json",out/"profile-work"]),
 ("calendar-freshness",[jdk/"bin/java","-Djava.awt.headless=true","-cp",str(classes)+os.pathsep+str(jar),"org.trillionnium.hepta.local.NativeCalendarDateProtocolHostTest",calendar,calendar/"work"])]
 try:
  for name,argv in commands:
   started=time.monotonic();result=subprocess.run(list(map(str,argv)),cwd=out,env=env,capture_output=True,timeout=120)
   for suffix,raw in (("stdout",result.stdout),("stderr",result.stderr)):(out/(name+"."+suffix)).write_bytes(raw)
   report["stages"].append(dict(name=name,argv=list(map(str,argv)),exit_code=result.returncode,elapsed_seconds=time.monotonic()-started,stdout=record(out/(name+".stdout")),stderr=record(out/(name+".stderr"))))
   require(result.returncode==0,"actual stage failed: "+name)
  live=json.loads((out/"LIVE-CASES.json").read_text());old=json.loads((out/"ORIGINAL-PROFILE-CASES.json").read_text());cal=json.loads((calendar/"CASES.json").read_text())
  require(live["all_pass"] is True and live["case_names"]==EXPECTED and live["cases"]==len(EXPECTED),"exact complete live case set required")
  require(old["all_pass"] is True and old["cases"]==22,"all original profile identity cases required")
  require(cal["all_pass"] is True and cal["cases"]==20 and any(x.get("name")=="capture_two_second_bound_rechecked_after_io" for x in cal["checks"]),"original calendar two-second cases required")
  report.update(live_cases=live,original_profile_cases=old,calendar_cases=cal,named_reports={"live_identity":record(out/"LIVE-CASES.json"),"original_profile":record(out/"ORIGINAL-PROFILE-CASES.json"),"calendar_freshness":record(calendar/"CASES.json")},all_pass=True)
 except Exception as error: report["error"]=type(error).__name__+": "+str(error)
 finally:
  report["source_inputs_after"]=[record(x) for x in originals];report["tools_after"]=[record(x) for x in tools]
  report["source_inputs_unchanged"]=before==report["source_inputs_after"];report["tools_unchanged"]=tool_before==report["tools_after"]
  report["all_pass"]=report["all_pass"] and report["source_inputs_unchanged"] and report["tools_unchanged"]
  (out/"RESULT.json").write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n")
 print(json.dumps({"all_pass":report["all_pass"],"error":report.get("error"),"live_cases":report.get("live_cases",{}).get("cases"),"result":str(out/"RESULT.json")}))
 return 0 if report["all_pass"] else 1
if __name__=="__main__":raise SystemExit(main())
