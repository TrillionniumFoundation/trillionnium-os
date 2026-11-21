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
 block=h.section(service,'    /** Native text capture mode is bound once','    synchronized TaskAuthorization.Gate bindTaskAuthorization(')
 for prefix in ['    private void bindNativeAxObservationRequest(ObservationRequest request){','    private boolean nativeTextObservationAllowed(ObservationRequest request,Graph graph){','    private void captureNativeAxObservation(ObservationRequest request){']:
  s=once(s,h.body(s,prefix),'')
 old=(source/'tests/native-observation-snapshot/SnapshotPipelineCases.fragment').read_text()
 s=once(s,old,block+(HERE/'AxPipelineCases.fragment').read_text())
 s=once(s,'        List<Object> nativeActionNodes;Map<String,Object> nativeActionWindows;int nativeActionWidth,nativeActionHeight;',
 '''        List<NativeActionSnapshotCheck.Node> nativeActionNodes;Map<String,Object> nativeActionWindows;int nativeActionWidth,nativeActionHeight;
        String nativeActionTaskId,nativeActionAuthorizationSha,nativeActionSelectionSha,nativeActionTargetSha,nativeActionGoalSha;
        long nativeActionCapturedAt;''')
 s=once(s,'    static final class NativeAppGoal {String ownerSha256,packageName;}',
 '''    static final class NativeAppGoal {
        static final String PRODUCT_PRICE="native_product_price",XIAOMI_PACKAGE="com.xiaomi.shop";String ownerSha256,packageName,kind;
    }
    static final class NativeCtripFlightPage {static boolean supported(NativeAppGoal goal){return false;}}
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
        static Runnable writeHook;static java.util.function.Consumer<byte[]> readHook;static int writes,reads;
        static final class Read {final File path;final byte[] bytes;
            Read(File p,byte[] b){path=p;bytes=b;}void unchangedPath()throws IOException{
                if(!Arrays.equals(bytes,Files.readAllBytes(path.toPath())))throw new IOException("host file changed");
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
            this.capture=capture;captureKind=ObservationCaptureEvidence.NATIVE_AX;
            if(live.phoneConstructHook!=null)live.phoneConstructHook.run();
        }''')
 h.write(path,s)
 return {'schema':'hepta.native-ax-extraction.v1','production_ax_methods_verbatim':True,
         'production_observer_original_methods_verbatim':True,'actual_helper_compiled':True,
         'ax_block_sha256':h.sha(block.encode()),'legacy_extraction':meta,
         'boundary':'Actual mode binding, both complete-census serialization, worker, receipt canonical-byte/hash validation, endpoint gates and publisher. Android graph/window/model capability/file endpoints are explicit fakes; actual full PhoneObservation also compiled by unchanged snapshot source closure. No phone/SDK/model execution.'}
def main():
 ap=argparse.ArgumentParser()
 for n in ['source','output','java-home','json-jar']:ap.add_argument('--'+n,type=Path,required=True)
 a=ap.parse_args();source=a.source.resolve();out=a.output.absolute();out.mkdir(parents=True,exist_ok=False)
 h=load(source/'tests/observation-diagnostics/run_host.py','ax_helpers')
 snap=load(source/'tests/native-observation-snapshot/run_host.py','ax_snapshot')
 java=a.java_home/'bin/java';javac=a.java_home/'bin/javac';jar=a.json_jar.resolve()
 if jar.stat().st_size!=78332 or h.sha(jar.read_bytes())!='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed':raise RuntimeError('JSON pin')
 deps=[source/PKG/n for n in snap.JAVA]
 profiles=[source/'src/org/trillionnium/hepta/background'/(n+'.java') for n in ['ProfileIdentity','ProfileTarget','WindowOwnership']]
 rect=source/'tests/qualification-scope/fixtures/android/graphics/Rect.java'
 fixtures=[source/'tests/native-observation-snapshot'/n for n in ['SnapshotChecks.java','ObservationEvidenceHost.java']]+[HERE/'ActualAxPhoneChecks.java']
 inputs=deps+profiles+[rect,*fixtures,HERE/'run_host.py',HERE/'AxPipelineCases.fragment',source/'tests/native-observation-snapshot/run_host.py',source/'tests/native-observation-snapshot/SnapshotPipelineCases.fragment',source/'tests/observation-pipeline/ObserverPipelineHost.template',source/'tests/observation-diagnostics/run_host.py']
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
