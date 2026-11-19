#!/usr/bin/env python3
"""Production screen-lease policy with explicit inert power and monotonic-clock ports."""
import argparse, hashlib, json, pathlib, shutil, subprocess, time

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--source',type=pathlib.Path)
    parser.add_argument('--output',type=pathlib.Path,required=True)
    parser.add_argument('--java-home',type=pathlib.Path)
    args=parser.parse_args()
    source=(args.source or pathlib.Path(__file__).resolve().parents[2]).resolve()
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    bg=source/'src/org/trillionnium/hepta/background'
    broker=(bg/'BackgroundDisplayBroker.java').read_text()
    framework=(bg/'PublicOwnGroupFramework.java').read_text()
    # Integration checks retain the actual port and lifecycle call sites; the Java test below
    # executes the production state machine, including a real concurrent acquire/retire race.
    exact={
        'only_three_argument_power_api':'PowerManager.class.getMethod("newWakeLock",int.class,String.class,int.class)',
        'create_before_activation':'                    verifyDisplay();\n                    acquirePublicScreenLease(created);',
        'cleanup_latch':'        closing.set(true);\n        retirePublicScreenLease();\n        retireBootRead();',
        'notes_quarantine':'    private void quarantinePublicNotes(String reason){\n        retirePublicScreenLease();',
        'profile_quarantine':'    private void quarantineProfile(String reason){\n        retirePublicScreenLease();',
        'absolute_watchdog':'if(publicScreenLease!=null)publicScreenLease.observeDeadline(now);',
        'private_mode_unchanged':'        if(config.publicOwnGroupScope==null)return;',
        'scoped_flags':'if(flags!=0x0000000a||selected!=displayId||selected<=1||remaining<=0||remaining>BrokerProtocol.MAX_TTL_MS',
        'physical_group_census':'need(type==1&&group!=owned.groupId,"PUBLIC_SCREEN_PHYSICAL_GROUP_REFUSED");',
    }
    for key,value in exact.items():
        actual=framework if key=='physical_group_census' else broker
        if value not in actual:raise RuntimeError('actual broker/framework power integration missing: '+key)
    if broker.count('token.acquire(remaining);')!=1 or broker.count('newDisplayWakeLock.invoke(')!=1:
        raise RuntimeError('screen lease must have one actual acquire site')
    start='    PublicOwnGroupScreenLease.Snapshot screenSnapshot(int id,String name)throws Exception{'
    end='    synchronized boolean hasFrozenIdentity()'
    if framework.count(start)!=1 or framework.count(end)!=1:raise RuntimeError('exact actual census hunk missing')
    census=framework[framework.index(start):framework.index(end)]
    fixture=out/'PublicScreenCensusFixture.java'
    fixture.write_text('''package org.trillionnium.hepta.background;
import java.io.IOException;import java.lang.reflect.Method;
final class PublicScreenCensusFixture {
 final Service service=new Service();final Object displayService=service;
 final Class<?> infoType=Info.class;final Method getAllDisplayIds,getDirectDisplayInfo;
 PublicScreenCensusFixture()throws Exception{
  getAllDisplayIds=Service.class.getMethod("getDisplayIds",boolean.class);
  getDirectDisplayInfo=Service.class.getMethod("getDisplayInfo",int.class);
 }
 public static final class Info {
  public int displayId,type,displayGroupId,state,flags=7040,ownerUid=0;
  public String name="hepta-bg-5bd0794d-bdaf-48ef-8dbf-f63c6befca85",uniqueId="virtual:owned",ownerPackageName="com.android.shell";
  Info(int id,int type,int group,int state){displayId=id;this.type=type;displayGroupId=group;this.state=state;}
 }
 public static final class Service {
  int[] ids={0,1,210},ending;int enumerations,directReads;
  final java.util.Map<Integer,Info> rows=new java.util.HashMap<Integer,Info>();
  Service(){rows.put(0,new Info(0,1,0,1));rows.put(1,new Info(1,1,1,2));rows.put(210,new Info(210,5,2,2));}
  public int[] getDisplayIds(boolean includeDisabled){if(!includeDisabled)throw new AssertionError("disabled displays omitted");
   enumerations++;return (enumerations>1&&ending!=null?ending:ids).clone();}
  public Info getDisplayInfo(int id){directReads++;return rows.get(id);}
 }
 private static void need(boolean ok,String message)throws IOException{if(!ok)throw new IOException(message);}
 private int field(Object info,String name)throws Exception{return infoType.getField(name).getInt(info);}
 private String text(Object info,String name)throws Exception{Object value=infoType.getField(name).get(info);
  need(value instanceof String&&!((String)value).isEmpty(),"unknown text");return (String)value;}
 private PublicOwnGroupPolicy.DisplayState display(int id,String name){return new PublicOwnGroupPolicy.DisplayState();}
'''+census+'''}
final class PublicOwnGroupPolicy {
 static final class DisplayState {
  final int flags=7040,ownerUid=0,groupId=2,physical0GroupId=0,physical1GroupId=1;
  final String name="hepta-bg-5bd0794d-bdaf-48ef-8dbf-f63c6befca85",uniqueId="virtual:owned",ownerPackage="com.android.shell";
 }
}
''')
    files=[bg/'PublicOwnGroupScreenLease.java',source/'tests/public-screen-lease/PublicOwnGroupScreenLeaseHostTest.java']
    files.append(fixture)
    inputs=files+[bg/'BackgroundDisplayBroker.java',bg/'PublicOwnGroupFramework.java',pathlib.Path(__file__).resolve()]
    def pin(p):
        data=p.read_bytes();return {'path':str(p),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
    before=[pin(p) for p in inputs]
    java=str(args.java_home/'bin/java') if args.java_home else (shutil.which('java') or 'java')
    compiler=[str(args.java_home/'bin/javac')] if args.java_home else ([shutil.which('javac')] if shutil.which('javac') else [java,'-m','jdk.compiler/com.sun.tools.javac.Main'])
    classes=out/'classes';classes.mkdir()
    commands=[('compile',compiler+['--release','8','-Xlint:all','-Werror','-encoding','UTF-8','-d',str(classes)]+list(map(str,files))),
              ('screen-lease',[java,'-cp',str(classes),'org.trillionnium.hepta.background.PublicOwnGroupScreenLeaseHostTest'])]
    report={'schema':'hepta.public-screen-lease-host-run.v1','phone_operations':0,'android_power_api_executed':False,
            'inputs_before':before,'integration_checks':list(exact),'actual_census_hunk_sha256':hashlib.sha256(census.encode()).hexdigest(),'stages':[]}
    for name,argv in commands:
        started=time.monotonic();result=subprocess.run(argv,capture_output=True,timeout=30)
        stdout=out/(name+'.stdout');stderr=out/(name+'.stderr');stdout.write_bytes(result.stdout);stderr.write_bytes(result.stderr)
        row={'name':name,'argv':argv,'exit_code':result.returncode,'elapsed_seconds':time.monotonic()-started,
             'stdout':pin(stdout),'stderr':pin(stderr)}
        report['stages'].append(row)
        if result.returncode:break
        if name=='screen-lease':report['test']=json.loads(result.stdout)
    report['inputs_after']=[pin(p) for p in inputs]
    report['passed']=len(report['stages'])==2 and all(row['exit_code']==0 for row in report['stages']) and report['inputs_before']==report['inputs_after']
    path=out/'RESULT.json';path.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'passed':report['passed'],'result':pin(path),'test':report.get('test')}))
    return 0 if report['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
