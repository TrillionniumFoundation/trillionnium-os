#!/usr/bin/env python3
"""Execute exact broker shutdown/retired-receipt hunks with explicit inert Android ports."""
import argparse,hashlib,importlib.util,json,pathlib,shutil,subprocess

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--source',type=pathlib.Path);ap.add_argument('--output',type=pathlib.Path,required=True);ap.add_argument('--java-home',type=pathlib.Path);ap.add_argument('--release8',action='store_true');args=ap.parse_args()
    root=pathlib.Path(__file__).resolve().parent;candidate=(args.source or root.parent).resolve();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    broker=candidate/'src/org/trillionnium/hepta/background/BackgroundDisplayBroker.java';raw=broker.read_text()
    def section(start,end):
        assert raw.count(start)==1 and raw.count(end)==1
        a=raw.index(start);return raw[a:raw.index(end,a)]
    methods=section('    private void beginPublicSurfaceDetach(){','    private JSONObject publicDetachEvidence()')
    delivery='''                    if(config.publicOwnGroupScope!=null)publicCreateReturnedHandle=created;
                    virtual = created;
                    if(config.publicOwnGroupScope!=null&&created!=null&&closing.get())startPublicSurfaceDetach(created);
'''
    precreate='''                    if(config.publicOwnGroupScope!=null&&publicCreateReturnedHandle!=null)
                        throw new BrokerProtocol.Refusal("PUBLIC_CREATE_HANDLE_ALREADY_BOUND");
'''
    assert raw.count(delivery)==1 and raw.count(precreate)==1
    retired=section('                    JSONObject retired=new JSONObject(new String(response,StandardCharsets.UTF_8));',
                    '                BrokerProtocol.writeFrame(accepted.getOutputStream(), response);')
    assert retired.endswith('                }\n');retired=retired[:-len('                }\n')]
    fixture=out/'fixture';fixture.mkdir();
    helper=candidate/'tests/background-session/prepare_fixture.py';spec=importlib.util.spec_from_file_location('json_host_fixture',helper)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);module.prepare(candidate,fixture/'base')
    java=fixture/'BrokerSurfaceAdapterFixture.java'
    prefix='''package org.trillionnium.hepta.background;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.json.JSONObject;
final class BrokerSurfaceAdapterFixture {
 static final class SystemClock {static long elapsedRealtime(){return System.nanoTime()/1000000;}}
 static final class Config {Object publicOwnGroupScope=new Object();}
 static final class VirtualDisplay {final int id;final String token;final AtomicInteger calls=new AtomicInteger();
  VirtualDisplay(int id,String token){this.id=id;this.token=token;}void setSurface(Object surface){if(surface!=null)throw new AssertionError("not detached");calls.incrementAndGet();}}
 static final class PublicOwnGroupFramework {boolean frozen=true;CountDownLatch reading,continueRead;
  boolean hasFrozenIdentity(){return frozen;}
  boolean frozenIdentityMatches(int id,String name){if(reading!=null){reading.countDown();try{continueRead.await();}catch(InterruptedException e){throw new IllegalStateException(e);}}return id==7&&"owned".equals(name);}}
 final Config config=new Config();final AtomicBoolean publicAdmissionRetired=new AtomicBoolean(),closing=new AtomicBoolean();
 final PublicOwnGroupSurfaceRetirement publicSurfaceRetirement=new PublicOwnGroupSurfaceRetirement();
 volatile VirtualDisplay virtual,publicCreateReturnedHandle;
 volatile boolean createInFlight;
 PublicOwnGroupFramework publicOwnGroupFramework=new PublicOwnGroupFramework();int displayId=7;String displayName="owned",state="ACTIVE";
 void deliverCreated(VirtualDisplay created){
'''
    suffix='''
 void closeScope(){closing.set(true);publicAdmissionRetired.set(true);beginPublicSurfaceDetach();}
 void beforeCreate()throws Exception {
'''+precreate+'''
 }
 byte[] retireSerializedReceipt(byte[] response)throws Exception {
  // The original adapter cases exercise non-calendar retirement only. Parse the
  // actual immutable Request type; this fixture does not authenticate or send it.
  final BrokerProtocol.Request request=BrokerProtocol.Request.parse(new JSONObject()
   .put("version",BrokerProtocol.PUBLIC_OWN_GROUP_VERSION)
   .put("request_id","00000000-0000-4000-8000-000000000001")
   .put("generation","00000000-0000-4000-8000-000000000002")
   .put("deadline_elapsed_ms",1).put("op","state")
   .put("display_scope_sha256","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
   .toString().getBytes(StandardCharsets.UTF_8));
'''+retired+'''return response;}
 private JSONObject publicDetachEvidence(){return new JSONObject(publicSurfaceRetirement.evidence());}
}
'''
    java.write_text(prefix+delivery+' }\n'+methods+suffix)
    test=fixture/'BrokerSurfaceAdapterHostTest.java'
    test.write_text('''package org.trillionnium.hepta.background;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.nio.charset.StandardCharsets;
import org.json.JSONObject;
public final class BrokerSurfaceAdapterHostTest {
 static int cases,checks;interface Work{void run()throws Exception;}
 static void yes(boolean b,String m){checks++;if(!b)throw new AssertionError(m);}
 static void test(String n,Work w)throws Exception{w.run();cases++;System.out.println("PASS "+n);}
 static void finished(BrokerSurfaceAdapterFixture f)throws Exception{long end=System.nanoTime()+2000000000L;
  while(System.nanoTime()<end){if(Boolean.TRUE.equals(f.publicSurfaceRetirement.evidence().get("worker_finished")))return;Thread.sleep(5);}throw new AssertionError("worker failed to finish");}
 static void unverified(BrokerSurfaceAdapterFixture f){Map<String,Object> e=f.publicSurfaceRetirement.evidence();
  yes(f.closing.get()&&f.publicAdmissionRetired.get(),"admission reopened");yes(Boolean.FALSE.equals(e.get("surface_stopped_verified")),"fake stop proof");}
 public static void main(String[] args)throws Exception{
  test("reused integer display id never replaces actual owned handle",()->{BrokerSurfaceAdapterFixture f=new BrokerSurfaceAdapterFixture();
   BrokerSurfaceAdapterFixture.VirtualDisplay old=new BrokerSurfaceAdapterFixture.VirtualDisplay(7,"old-token"),replacement=new BrokerSurfaceAdapterFixture.VirtualDisplay(7,"new-token");
   f.deliverCreated(old);f.closeScope();finished(f);yes(old.calls.get()==1&&replacement.calls.get()==0,"new display was touched by integer id");unverified(f);});
  test("initial create returned handle needs no policy activation to shut down",()->{BrokerSurfaceAdapterFixture f=new BrokerSurfaceAdapterFixture();f.publicOwnGroupFramework.frozen=false;
   BrokerSurfaceAdapterFixture.VirtualDisplay old=new BrokerSurfaceAdapterFixture.VirtualDisplay(7,"initial-token");f.deliverCreated(old);f.closeScope();finished(f);
   yes(old.calls.get()==1&&"CREATE_RETURNED_HANDLE_ONLY".equals(f.publicSurfaceRetirement.evidence().get("identity_source")),"initial handle gate prevented shutdown");unverified(f);});
  test("late actual create return after no-handle retirement is delivered once",()->{BrokerSurfaceAdapterFixture f=new BrokerSurfaceAdapterFixture();f.publicOwnGroupFramework.frozen=false;f.closeScope();finished(f);
   yes(Boolean.FALSE.equals(f.publicSurfaceRetirement.evidence().get("api_attempted")),"no-handle path claimed a call");
   BrokerSurfaceAdapterFixture.VirtualDisplay late=new BrokerSurfaceAdapterFixture.VirtualDisplay(7,"late-token");f.deliverCreated(late);
   long end=System.nanoTime()+2000000000L;while(late.calls.get()==0&&System.nanoTime()<end)Thread.sleep(5);finished(f);
   yes(late.calls.get()==1,"late owned handle not detached");f.closeScope();Thread.sleep(10);yes(late.calls.get()==1,"retirement retried actual API");unverified(f);});
  test("second create is refused before an API can replace the handle",()->{BrokerSurfaceAdapterFixture f=new BrokerSurfaceAdapterFixture();f.beforeCreate();
   f.deliverCreated(new BrokerSurfaceAdapterFixture.VirtualDisplay(7,"first"));try{f.beforeCreate();throw new AssertionError("second create admitted");}
   catch(BrokerProtocol.Refusal expected){yes("PUBLIC_CREATE_HANDLE_ALREADY_BOUND".equals(expected.code),"wrong refusal");}});
  test("last handle check failure records no actual API entry",()->{BrokerSurfaceAdapterFixture f=new BrokerSurfaceAdapterFixture();
   BrokerSurfaceAdapterFixture.VirtualDisplay old=new BrokerSurfaceAdapterFixture.VirtualDisplay(7,"old"),other=new BrokerSurfaceAdapterFixture.VirtualDisplay(7,"replacement");
   f.deliverCreated(old);f.publicOwnGroupFramework.reading=new CountDownLatch(1);f.publicOwnGroupFramework.continueRead=new CountDownLatch(1);f.closeScope();
   yes(f.publicOwnGroupFramework.reading.await(2,TimeUnit.SECONDS),"not at final identity boundary");f.virtual=other;f.publicOwnGroupFramework.continueRead.countDown();finished(f);
   yes(old.calls.get()==0&&other.calls.get()==0&&!Boolean.TRUE.equals(f.publicSurfaceRetirement.evidence().get("api_attempted")),"unexecuted or foreign API recorded");unverified(f);});
  test("scope retirement preserves an already dispatched effect receipt",()->{BrokerSurfaceAdapterFixture f=new BrokerSurfaceAdapterFixture();f.closeScope();finished(f);
   JSONObject old=new JSONObject().put("ok",true).put("state","ACTIVE").put("dispatched",true).put("public_own_group_readback_wire","old-wire").put("request_id","same-request");
   JSONObject after=new JSONObject(new String(f.retireSerializedReceipt(old.toString().getBytes(StandardCharsets.UTF_8)),StandardCharsets.UTF_8));
   yes(!after.getBoolean("ok")&&after.getBoolean("dispatched"),"retirement rewrote real effect as undispatched");yes(after.getBoolean("public_scope_closing")&&after.getBoolean("public_scope_admission_retired"),"retirement markers absent");
   yes(after.isNull("public_own_group_readback_wire")&&"same-request".equals(after.getString("request_id")),"old authority or wrong receipt id");});
  test("scope retirement also preserves a truly undispatched request",()->{BrokerSurfaceAdapterFixture f=new BrokerSurfaceAdapterFixture();
   JSONObject old=new JSONObject().put("ok",true).put("dispatched",false);JSONObject after=new JSONObject(new String(f.retireSerializedReceipt(old.toString().getBytes(StandardCharsets.UTF_8)),StandardCharsets.UTF_8));
   yes(!after.getBoolean("dispatched"),"undispatched event promoted");});
  System.out.println("{\\"cases\\":"+cases+",\\"assertions\\":"+checks+",\\"all_pass\\":true,\\"phone_contacted\\":false,\\"actual_android_api_executed\\":false}");
 }
}
''')
    bg=candidate/'src/org/trillionnium/hepta/background'
    names=['BrokerProtocol','PublicPermissionControllerUi','FixedIntentTools','FixedIntentTarget','ProfileIdentity','ProfileTarget','PublicOwnGroupPolicy','PublicOwnGroupSurfaceRetirement']
    files=[bg/(n+'.java') for n in names]+[java,test]+list(sorted((fixture/'base/org/json').glob('*.java')))
    classes=out/'classes';classes.mkdir()
    if args.java_home:
        java_cmd=str(args.java_home.resolve()/'bin/java');javac=str(args.java_home.resolve()/'bin/javac')
        if not pathlib.Path(java_cmd).is_file() or not pathlib.Path(javac).is_file():raise SystemExit('Specified Java home must provide both java and javac')
        compiler=[javac]
    else:
        java_cmd=shutil.which('java') or 'java';compiler=[shutil.which('javac')] if shutil.which('javac') else [java_cmd,'-m','jdk.compiler/com.sun.tools.javac.Main']
    flags=['--release','8','-Xlint:all'] if args.release8 else ['-source','8','-target','8','-Xlint:all,-options']
    commands=[('compile',compiler+flags+['-Werror','-encoding','UTF-8','-d',str(classes),*map(str,files)]),
              ('adapter',[java_cmd,'-cp',str(classes),'org.trillionnium.hepta.background.BrokerSurfaceAdapterHostTest'])]
    report={'schema':'hepta.public-own-group.broker-adapter-host.v1','status':'NOT_DEPLOYED','phone_contacted':False,
            'actual_android_api_executed':False,'actual_broker_hunks_executed':True,'fake_ports':['VirtualDisplay.setSurface','framework frozen evidence','SystemClock','org.json'],
            'broker_source_sha256':hashlib.sha256(raw.encode()).hexdigest(),
            'retired_receipt_context':'Actual Request.parse of fixed public-scope state request; surrounding socket/authentication are not exercised and calendar branches are not covered by these legacy cases.',
            'hunk_sha256':{name:hashlib.sha256(value.encode()).hexdigest() for name,value in [('shutdown',methods),('create_return',delivery),('duplicate_create_guard',precreate),('retired_receipt',retired)]},
            'source_sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in files},'stages':[]}
    for name,argv in commands:
        run=subprocess.run(argv,capture_output=True,text=True,timeout=30);(out/(name+'.stdout')).write_text(run.stdout);(out/(name+'.stderr')).write_text(run.stderr)
        stage={'name':name,'exit_code':run.returncode};report['stages'].append(stage);print(name,run.returncode,run.stdout[-1000:].strip())
        if name=='adapter' and run.returncode==0:stage['result']=json.loads(run.stdout.strip().splitlines()[-1])
        if run.returncode:print(run.stderr[-8000:]);break
    report['source_unchanged']=hashlib.sha256(broker.read_bytes()).hexdigest()==report['broker_source_sha256']
    report['passed']=len(report['stages'])==len(commands) and all(s['exit_code']==0 for s in report['stages']) and report['source_unchanged']
    (out/'RESULT.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'passed':report['passed'],'output':str(out)}));return 0 if report['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
