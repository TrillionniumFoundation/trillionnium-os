#!/usr/bin/env python3
"""Run verbatim AX producer/mode/worker/publication with explicit host IO fakes.
This is source-level evidence, not Android/device/NPU/business qualification."""
import argparse,importlib.util,json,os
from pathlib import Path
HERE=Path(__file__).resolve().parent
BUNDLE=HERE.parents[1]
PKG=Path('src/org/trillionnium/hepta/local')
def load(path,name):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def once(text,before,after):
 if text.count(before)!=1:raise RuntimeError('nonunique AX extraction boundary: '+before[:120])
 return text.replace(before,after,1)
def generate(source,out,h,snap):
 base=out/'base';base.mkdir();meta=snap.generate(source,base,h)
 path=out/'ObserverPipelineHost.java';s=(base/'ObserverPipelineHost.java').read_text()
 service=(source/PKG/'HeptaAccessibilityService.java').read_text()
 # The shared legacy template has a diagnostic-only PACKAGE type port.
 # This dedicated AX bridge supplies the real provider constants/predicate below.
 # Remove only that exact duplicate; keep the three fail-only diagnostic methods.
 diagnostic_provider_port='    private static final class NativeCtripFlightPage {static final String PACKAGE="ctrip.android.view";}\n'
 s=once(s,diagnostic_provider_port,'')
 # This legacy AX bridge has a nested Node-only type port. Qualify only the new
 # pure-value carrier's two Snapshot references to the already compiled top-level type.
 # The dedicated real form/sampling bridge does not call this generator.
 sampling_carrier=h.body(service,'    private static final class CtripFormSample {')
 sampling_carrier_proof=sampling_carrier
 if h.sha(sampling_carrier.encode())!='abd251e1d042c25f814088fd3b8af56e6bf4452700b5fae226890ae6d1172749':
  if len(sampling_carrier.encode())!=1759 or h.sha(sampling_carrier.encode())!='f9a1dc4d0fc7cb143bdeb2362c067169e5baab545400a32a4686288e67d2f662':raise RuntimeError('exact reviewed dual-clock sampling carrier required')
  for revised,prior in [("        // The latest census acceptance and the Gate's unchanged-key timestamp are distinct clocks.\n        final String requestId;final long epoch,acceptedAt,gateAcceptedAt,readStartedAt,readCompletedAt,completedAt;\n", '        final String requestId;final long epoch,acceptedAt,readStartedAt,readCompletedAt,completedAt;\n'), ('            requestId=request.requestId;this.epoch=epoch;acceptedAt=-1;gateAcceptedAt=-1;readOrdinal=request.readWorksStarted;\n', '            requestId=request.requestId;this.epoch=epoch;acceptedAt=-1;readOrdinal=request.readWorksStarted;\n'), ('        CtripFormSample(CtripFormSample value,long acceptedAt,long gateAcceptedAt){\n            requestId=value.requestId;epoch=value.epoch;this.acceptedAt=acceptedAt;this.gateAcceptedAt=gateAcceptedAt;readOrdinal=value.readOrdinal;\n', '        CtripFormSample(CtripFormSample value,long acceptedAt){\n            requestId=value.requestId;epoch=value.epoch;this.acceptedAt=acceptedAt;readOrdinal=value.readOrdinal;\n')]:
   if sampling_carrier_proof.count(revised)!=1:raise RuntimeError('unique complete sampling carrier inverse required')
   sampling_carrier_proof=sampling_carrier_proof.replace(revised,prior,1)
 if len(sampling_carrier_proof.encode())!=1571 or h.sha(sampling_carrier_proof.encode())!='abd251e1d042c25f814088fd3b8af56e6bf4452700b5fae226890ae6d1172749':
  raise RuntimeError('exact actual Ctrip sampling carrier before AX-only type qualification')
 short_snapshot='NativeActionSnapshotCheck.Snapshot'
 full_snapshot='org.trillionnium.hepta.local.NativeActionSnapshotCheck.Snapshot'
 if sampling_carrier.count(short_snapshot)!=2:raise RuntimeError('exact two sampling Snapshot type references')
 sampling_carrier_host=sampling_carrier.replace(short_snapshot,full_snapshot)
 sampling_carrier_host_proof=sampling_carrier_proof.replace(short_snapshot,full_snapshot)
 if (len(sampling_carrier_host_proof.encode())!=1629
     or h.sha(sampling_carrier_host_proof.encode())!='5eced13663d08a02f108033e451834b1a2a1eaf156735a9b772e835b764c998c'
     or sampling_carrier_host.count(full_snapshot)!=2
     or sampling_carrier_host.replace(full_snapshot,short_snapshot)!=sampling_carrier):
  raise RuntimeError('AX-only carrier must reverse in full to the actual source member')
 s=once(s,sampling_carrier,sampling_carrier_host)
 block=h.section(service,'    /** Native text capture mode is bound once','    synchronized TaskAuthorization.Gate bindTaskAuthorization(')
 # The later manual pixel/census publisher is a separate, fail-closed product
 # entry. The legacy AX suite has no manual owner or pixel publication ports.
 # Exclude only its exact complete block; every AX producer method stays verbatim.
 original_ax_block_sha256=h.sha(block.encode());manual_capture_exclusion=None
 manual_start='    /** Copies the already published complete graph and releases its SDK references.'
 manual_end='    synchronized void bindNativeTextObservation('
 if manual_start in block:
  if block.count(manual_start)!=1 or block.count(manual_end)!=1:
   raise RuntimeError('unique complete manual capture block required')
  manual_block=h.section(block,manual_start,manual_end)
  if len(manual_block.encode())!=7913 or h.sha(manual_block.encode())!='cd70667313f0ec76656b0fb0a740985334412df4a9cad06cc05382c7696c4599':
   raise RuntimeError('exact reviewed manual-only capture block required')
  block=once(block,manual_block,'')
  manual_capture_exclusion={'bytes':len(manual_block.encode()),'sha256':h.sha(manual_block.encode()),
                            'compiled_by_dedicated_manual_and_android_closures':True,
                            'manual_authority_not_ported_into_legacy_ax':True}
 for prefix in ['    private void bindNativeAxObservationRequest(ObservationRequest request){','    private boolean nativeTextObservationAllowed(ObservationRequest request,Graph graph){','    private void captureNativeAxObservation(ObservationRequest request){']:
  s=once(s,h.body(s,prefix),'')
 old=(source/'tests/native-observation-snapshot/SnapshotPipelineCases.fragment').read_text()
 s=once(s,old,block+(HERE/'AxPipelineCases.fragment').read_text())
 s=once(s,'        List<Object> nativeActionNodes;Map<String,Object> nativeActionWindows;int nativeActionWidth,nativeActionHeight;',
 '''        List<NativeActionSnapshotCheck.Node> nativeActionNodes;Map<String,Object> nativeActionWindows;int nativeActionWidth,nativeActionHeight;
        String nativeActionTaskId,nativeActionAuthorizationSha,nativeActionSelectionSha,nativeActionTargetSha,nativeActionGoalSha;
        long nativeActionCapturedAt;''')
 s=once(s,'import java.util.*;','import java.util.*;\nimport org.trillionnium.hepta.background.ProfileTarget;')
 provider=(source/PKG/'NativeCtripFlightPage.java').read_text()
 goal=(source/PKG/'NativeAppGoal.java').read_text()
 import re
 goal_kind=re.findall(r'FLIGHT_RESULTS\s*=\s*"([^"]+)"',goal)
 if len(goal_kind)!=1:raise RuntimeError('actual native flight goal boundary')
 supported=h.body(provider,'    static boolean supported(NativeAppGoal goal){')
 product_supported=h.body(goal,'    public boolean readsXiaomiProduct(){')
 constants=[]
 for marker in ['static final String PACKAGE=', 'static final long VERSION_CODE=', 'static final String BASE_APK_SHA256=', 'static final String HOME=']:
  matches=[line.strip() for line in provider.splitlines() if marker in line]
  if len(matches)!=1:raise RuntimeError('actual Ctrip provider constant boundary')
  constants.append(matches[0])
 s=once(s,'    static final class NativeAppGoal {String ownerSha256,packageName;}',
 '''    static final class NativeAppGoal {
        static final String PRODUCT_PRICE="native_product_price",XIAOMI_PACKAGE="com.xiaomi.shop";
        static final String CTRIP_PACKAGE="ctrip.android.view",FLIGHT_RESULTS="native_flight_results";
        static final String PRODUCT_ORDER_PREVIEW="native_product_order_preview",PRODUCT_MODEL="AX3000T";
        String ownerSha256,packageName,kind,fromCity,toCity,productModel;int adults,children,infants;Object orderPreview;
        ACTUAL_XIAOMI_PROVIDER_VALUE_PREDICATE
    }
    static final class NativeCtripFlightPage { ACTUAL_CTRIP_PROVIDER_VALUE_PREDICATE }
    static final class LocalInference {final boolean visual;LocalInference(boolean v){visual=v;}boolean acceptsObservedImage(){return visual;}}
    static final class LocalRuntimeConfig {
        static final class Profile {final boolean visual;Profile(boolean v){visual=v;}boolean visual(){return visual;}}
        final Profile profile;LocalRuntimeConfig(boolean v){profile=new Profile(v);}
    }
    static final class TaskAuthorization {static final class Gate {}}
    static final class NativeActionSnapshotCheck {
        static final class Node {final Map<String,Object> v;Node(Map<String,Object> v){this.v=ObservationCaptureEvidence.freezeMap(v);}}
    }
    private boolean ownsAuthorization(String task,Object auth){return owns(task)&&auth!=null&&auth==taskAuthorization;}
    static final class MobiMindPrivateFiles {
        static Runnable writeHook,unchangedHook;static java.util.function.Consumer<byte[]> readHook;static int writes,reads;
        static final class Read {final File path;final byte[] bytes;
            Read(File p,byte[] b){path=p;bytes=b;}void unchangedPath()throws IOException{
                if(!Arrays.equals(bytes,Files.readAllBytes(path.toPath())))throw new IOException("host file changed");
                if(unchangedHook!=null)unchangedHook.run();
            }}
        static void writeNew(File path,byte[] bytes)throws IOException{
            expect(!isMain(),"private write on main");writes++;
            Files.createFile(path.toPath(),java.nio.file.attribute.PosixFilePermissions.asFileAttribute(java.nio.file.attribute.PosixFilePermissions.fromString("rw-------")));
            try(java.nio.channels.FileChannel ch=java.nio.channels.FileChannel.open(path.toPath(),StandardOpenOption.WRITE)){
                java.nio.ByteBuffer b=java.nio.ByteBuffer.wrap(bytes);while(b.hasRemaining())ch.write(b);ch.force(true);
            }if(writeHook!=null)writeHook.run();
        }
        static Read read(File path,int max,boolean owned)throws IOException{
            expect(!isMain(),"private read on main");reads++;byte[] bytes=Files.readAllBytes(path.toPath());
            if(bytes.length>max)throw new IOException("host bound");if(readHook!=null)readHook.accept(bytes);
            return new Read(path,bytes);
        }
    }''')
 s=once(s,'ACTUAL_CTRIP_PROVIDER_VALUE_PREDICATE','\n'.join(constants)+'\n'+supported)
 s=once(s,'ACTUAL_XIAOMI_PROVIDER_VALUE_PREDICATE',product_supported)
 s=once(s,'FLIGHT_RESULTS="native_flight_results"','FLIGHT_RESULTS="'+goal_kind[0]+'"')
 s=once(s,'        Object profileTarget(){return null;} // Explicit scheduling fixture has no profile selection.',
     '        ProfileTarget observedProfileTarget;ProfileTarget profileTarget(){return observedProfileTarget;} // Explicit synthetic profile transport; no phone permission.')
 s=once(s,'    static final class BackgroundSession {',
 '''    static final class BackgroundSession {
        // Fail-only legacy port; the empty-loading suite substitutes the actual
        // same-object broker proof registry and production historical check.
        void requireHistoricalProfileWindow(WindowOwnership proof,int windowId,int observedTaskId,long capturedAt){
            throw new AssertionError("legacy AX fixture cannot grant profile loading retries");
        }''')
 profile_adapter=h.body((source/PKG/'NativeAppEvidence.java').read_text(),'    static Map<String,Object> profileActionIdentity(WindowOwnership actual){')
 s=once(s,'import org.trillionnium.hepta.background.ProfileTarget;','import org.trillionnium.hepta.background.ProfileTarget;\nimport org.trillionnium.hepta.background.WindowOwnership;')
 s=once(s,h.body(s,'    static final class WindowOwnership {'),'')

 s=once(s,'    static final class NativeAppSession {',
 '''    static final class NativeAppSession {
        Object authorization;String taskId,generation;Selection selection;BackgroundTaskTarget target;NativeAppGoal goal;int displayId;''')
 s=once(s,'    static final class NativeAppEvidence {',
 '''    static final class NativeAppEvidence {
        static Map<String,Object> profileActionIdentity(WindowOwnership ignored){throw new AssertionError("host user0 has no profile proof");}''')
 s=once(s,'    static final class PhoneObservation {',
 '''    static final class PhoneObservation {
        ObservationCaptureEvidence capture;String captureKind=ObservationCaptureEvidence.PIXELS;
        PhoneObservation(String id,String pkg,long at,int width,int height,int rotation,int window,Rect bounds,
            File image,String hash,String tree,Object state,Object metadata,boolean truncated,Object rows,String generation,String initial,
            List<String> allowed,Object stats,JSONObject selection,String owner,Map<String,Object> evidence,WindowOwnership profile,ObservationCaptureEvidence capture){
            this(id,pkg,at,width,height,rotation,window,bounds,image,hash,tree,state,metadata,truncated,rows,generation,initial,allowed,stats,selection,owner,evidence,profile);
            expect(image==null&&hash==null&&capture!=null,"explicit AX carrier is not pixels");
            this.capture=capture;captureKind=capture.kind;
            if(live.phoneConstructHook!=null)live.phoneConstructHook.run();
        }''')
 s=once(s,'        static Map<String,Object> profileActionIdentity(WindowOwnership ignored){throw new AssertionError("host user0 has no profile proof");}',profile_adapter)
 # The AX block consumes the production typed read failure and the same pure
 # window fingerprint as the post-effect bridge. Replace the legacy read port
 # and compile complete current members; no historical proof is compiled here.
 actual_stale=h.body(service,'    private static final class StaleObservation extends IllegalStateException {')
 stale_port=h.body(s,'    static final class StaleObservation extends IllegalStateException {')
 s=once(s,stale_port,actual_stale)
 fingerprint=h.body(service,'    private static String postEffectChildWindowFingerprint(')
 evidence=(source/PKG/'NativeAppEvidence.java').read_text()
 value_members={name:h.body(evidence,anchor) for name,anchor in {
     'fingerprint':'    static String fingerprint(',
     'canonical':'    private static void canonical(',
     'hash':'    static String hash(',
     'need':'    static void need(',
 }.items()}
 s=once(s,'    static final class NativeAppEvidence {',
     '    static final class NativeAppEvidence {\n'+'\n'.join(value_members.values()))
 s=once(s,'import java.security.MessageDigest;',
     'import java.security.MessageDigest;\nimport java.security.NoSuchAlgorithmException;')
 s=once(s,'    static ObservationCaptureEvidence phoneCapture;',
     fingerprint+'\n    static ObservationCaptureEvidence phoneCapture;')
 retry_members={'actual_stale':actual_stale,'child_window_fingerprint':fingerprint,**value_members}
 for name,member in retry_members.items():
  if s.count(member)!=1:raise RuntimeError('complete actual AX retry dependency must occur exactly once: '+name)
 h.write(path,s)
 return {'schema':'hepta.native-ax-extraction.v1','production_ax_methods_verbatim':True,
         'production_observer_original_methods_verbatim':True,'actual_helper_compiled':True,
         'ax_block_sha256':h.sha(block.encode()),'legacy_extraction':meta,
         'original_ax_block_sha256':original_ax_block_sha256,'manual_capture_exclusion':manual_capture_exclusion,
         'actual_ax_retry_dependencies':{name:{'bytes':len(member.encode()),'sha256':h.sha(member.encode())} for name,member in retry_members.items()},
         'actual_stale_replaces_legacy_read_port':True,'retry_dependency_members_verbatim':True,
         'diagnostic_provider_port_removed_sha256':h.sha(diagnostic_provider_port.encode()),
         'actual_provider_value_members_unchanged':True,
         'sampling_carrier_type_qualification':{
             'actual_member_bytes':len(sampling_carrier.encode()),'actual_member_sha256':h.sha(sampling_carrier.encode()),
             'host_member_bytes':len(sampling_carrier_host.encode()),'host_member_sha256':h.sha(sampling_carrier_host.encode()),
             'only_two_snapshot_type_names_qualified':True,'whole_member_inverse_equal':True,
             'reviewed_712_carrier_proof_sha256':h.sha(sampling_carrier_proof.encode()),'clock_inverse_proof_copy_only':True,
             'legacy_nested_node_port_unchanged':True,'real_form_bridge_uses_original_member':True,
             'actual_top_level_snapshot_source':h.meta(source/PKG/'NativeActionSnapshotCheck.java')},
         'boundary':'Actual mode binding, both complete-census serialization, worker, receipt canonical-byte/hash validation, endpoint gates and publisher. Android graph/window/model capability/file endpoints are explicit fakes; actual full PhoneObservation also compiled by unchanged snapshot source closure. No phone/SDK/model execution.'}
def main():
 ap=argparse.ArgumentParser()
 for n in ['source','output','java-home','json-jar']:ap.add_argument('--'+n,type=Path,required=True)
 a=ap.parse_args();source=a.source.resolve();out=a.output.absolute();out.mkdir(parents=True,exist_ok=False)
 h=load(source/'tests/observation-diagnostics/run_host.py','ax_helpers')
 snap=load(source/'tests/native-observation-snapshot/run_host.py','ax_snapshot')
 java=a.java_home/'bin/java';javac=a.java_home/'bin/javac';jar=a.json_jar.resolve()
 if jar.stat().st_size!=78332 or h.sha(jar.read_bytes())!='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed':raise RuntimeError('JSON pin')
 deps_png=h.png_sources(source)
 deps=[source/PKG/n for n in snap.JAVA]+[source/PKG/n for n in ['NativeXiaomiSearchInputObservation.java','NativeCtripFormObservation.java','NativeActionSnapshotCheck.java','ObservedTargetLabels.java']]+deps_png
 profiles=[source/'src/org/trillionnium/hepta/background'/(n+'.java') for n in ['ProfileIdentity','ProfileTarget','WindowOwnership']]
 rect=source/'tests/qualification-scope/fixtures/android/graphics/Rect.java'
 fixtures=[source/'tests/native-observation-snapshot'/n for n in ['SnapshotChecks.java','ObservationEvidenceHost.java']]+[HERE/'ActualAxPhoneChecks.java']
 inputs=deps+[source/PKG/'NativeCtripFlightPage.java',source/PKG/'NativeAppGoal.java']+profiles+[rect,*fixtures,HERE/'run_host.py',HERE/'AxPipelineCases.fragment',source/'tests/native-observation-snapshot/run_host.py',source/'tests/native-observation-snapshot/SnapshotPipelineCases.fragment',source/'tests/observation-pipeline/ObserverPipelineHost.template',source/'tests/observation-diagnostics/run_host.py']
 tools=[java,javac,a.java_home/'lib/modules',a.java_home/'lib/ct.sym',jar]
 before=[h.meta(p) for p in inputs];tool_before=[h.meta(p) for p in tools]
 result={'schema':'hepta.native-ax-host.v1','all_pass':False,'stages':[],'input_before':before,'tools_before':tool_before,
         'phone_execution':False,'android_execution':False,'sdk_loaded':False,'model_executed':False,'business_completion_verified':False,
         'action_freshness_relaxed':False,'deadline_expanded':False}
 try:
  gen=out/'generated';gen.mkdir();h.save(out/'EXTRACTION.json',generate(source,gen,h,snap));classes=out/'classes';classes.mkdir()
  sources=[p for p in deps if p.name not in ['HeptaAccessibilityService.java','LocalTaskController.java','NativeAppEvidence.java']]+profiles+fixtures+[rect,gen/'ObserverPipelineHost.java']
  result['stages'].append(h.stage('compile',[str(javac),'--release','8','-encoding','UTF-8','-Xlint:all','-Werror','-cp',str(jar),'-d',str(classes)]+list(map(str,sources)),out))
  if result['stages'][-1]['exit_code']!=0:raise RuntimeError('actual AX extraction compile failed')
  result['stages'].append(h.stage('cases',[str(java),'-cp',str(classes)+os.pathsep+str(jar),'org.trillionnium.hepta.local.ObserverPipelineHost',str(out/'CASES.json')],out))
  if (out/'CASES.json').exists():result['cases']=json.loads((out/'CASES.json').read_text())
  if result['stages'][-1]['exit_code']!=0:raise RuntimeError('actual AX producer cases failed')
  cases=result['cases']
  if cases['all_pass'] is not True or len(cases['case_names'])!=cases['cases'] or len(set(cases['case_names']))!=cases['cases']:raise RuntimeError('AX case accounting')
  result['all_pass']=True
 except Exception as e:result['error']={'type':type(e).__name__,'message':str(e)}
 finally:
  result['input_after']=[h.meta(p) for p in inputs];result['tools_after']=[h.meta(p) for p in tools]
  result['inputs_unchanged']=before==result['input_after'];result['tools_unchanged']=tool_before==result['tools_after']
  result['all_pass']=result['all_pass'] and result['inputs_unchanged'] and result['tools_unchanged'];h.save(out/'RESULT.json',result)
 print(json.dumps({'all_pass':result['all_pass'],'error':result.get('error'),'cases':result.get('cases',{}).get('cases'),'result':h.meta(out/'RESULT.json')}))
 return 0 if result['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
