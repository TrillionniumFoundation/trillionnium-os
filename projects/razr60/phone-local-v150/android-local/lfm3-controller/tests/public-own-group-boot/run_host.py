#!/usr/bin/env python3
"""Actual boot fence/reader and exact broker cancellation hunks, using owned host children only."""
from pathlib import Path
import argparse, hashlib, json, re, subprocess, time

p=argparse.ArgumentParser()
p.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parents[2])
p.add_argument('--out',type=Path,required=True)
p.add_argument('--jdk-bin',type=Path,required=True)
a=p.parse_args();root=a.source_root.resolve();out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
classes=out/'classes';classes.mkdir();bg=root/'src/org/trillionnium/hepta/background'
raw=(bg/'BackgroundDisplayBroker.java').read_text()
def exact(start,end):
    assert raw.count(start)==1 and raw.count(end)==1
    begin=raw.index(start);return raw[begin:raw.index(end,begin)]
halt=exact('    private void retireBootRead() {','    private void beginCleanup(String reason) {')
cleanup=exact('    private void beginCleanup(String reason) {','        if(publicNotesCustody!=null)publicNotesCustody.retireAdmission();')+'    }\n'
screen_retire=re.findall(r'(?m)^    private void retirePublicScreenLease\(\)\{[^\n]+\}$',raw)
assert len(screen_retire)==1
known_branch=re.search(r'if\(config.profileTarget!=null&&profileCustody.known\(\)\)\{\n(.*?)\n\s*\}',raw,re.S).group(1)
assert raw.count('private final ProfileRecoveryBootCount publicBootCount=new ProfileRecoveryBootCount(SystemClock::elapsedRealtime);')==1
assert raw.count('shell,displays,config.publicOwnGroupScope,publicBootCount,Math.min(expires,started+STARTUP_MS)')==1
assert raw.count('Runtime.getRuntime().halt(')==1 and raw.count('haltAfterBootRead(0);')==2 and raw.count('haltAfterBootRead(known ? 0 : 70);')==1
framework=(bg/'PublicOwnGroupFramework.java').read_text()
assert 'Settings.Global.getInt' not in framework and 'getContentResolver' not in framework
assert framework.count('PublicOwnGroupBootIdentity.requireCurrent(bootCount,scope.bootCount,\n                SystemClock.elapsedRealtime(),initializationDeadline);')==1
fixture=out/'BrokerBootLifecycleFixture.java'
fixture.write_text('''package org.trillionnium.hepta.background;
import java.util.concurrent.atomic.AtomicBoolean;
final class BrokerBootLifecycleFixture {
 final AtomicBoolean closing=new AtomicBoolean();final ProfileRecoveryBootCount publicBootCount;volatile String bootReadRetirementFailure;
 PublicOwnGroupScreenLease publicScreenLease;
 String state="INITIAL";final java.util.List<String> terminalStates=new java.util.ArrayList<String>();
 BrokerBootLifecycleFixture(ProfileRecoveryBootCount reader){publicBootCount=reader;}
 static final class Halted extends Error {private static final long serialVersionUID=1L;final int exit;Halted(int exit){this.exit=exit;}}
 static final class Runtime {static Runtime getRuntime(){return new Runtime();}void halt(int exit){throw new Halted(exit);}}
 boolean cleanupEntryReturned;void cleanup(){beginCleanup("host_test");cleanupEntryReturned=true;}void halt(int exit){haltAfterBootRead(exit);}
 String released(){return releasedState();}
 void printTerminal(){terminalStates.add(state);}
 void watchdogKnown(){
'''+known_branch+'\n }\n'+halt+cleanup+screen_retire[0]+'\n}\n')
names=['BrokerProtocol','PublicPermissionControllerUi','FixedIntentTools','FixedIntentTarget','ProfileIdentity','ProfileTarget','PublicOwnGroupPolicy',
       'ProfileRecoveryBootCount','PublicOwnGroupBootIdentity','PublicOwnGroupScreenLease']
sources=[bg/(n+'.java') for n in names]+[fixture,Path(__file__).resolve().parent/'PublicOwnGroupBootIdentityHostTest.java']
def ident(path):
    raw=path.read_bytes();return {'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
report={'schema':'hepta.public-scope-boot-host-run.v1','phone_contacted':False,'android_runtime':False,'sources':[ident(x) for x in sources],
        'broker':ident(bg/'BackgroundDisplayBroker.java'),'framework':ident(bg/'PublicOwnGroupFramework.java'),
        'exact_hunks':{k:hashlib.sha256(v.encode()).hexdigest() for k,v in [('halt',halt),('cleanup_entry',cleanup),('watchdog_known_branch',known_branch),('screen_retirement',screen_retire[0])]},'commands':[]}
commands=[('compile',[str(a.jdk_bin/'javac'),'--release','8','-Xlint:all,-options','-Werror','-proc:none','-d',str(classes)]+[str(x) for x in sources],30),
          ('test',[str(a.jdk_bin/'java'),'-cp',str(classes),'org.trillionnium.hepta.background.PublicOwnGroupBootIdentityHostTest'],20)]
for name,argv,timeout in commands:
    started=time.monotonic();run=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
    (out/(name+'.stdout')).write_bytes(run.stdout);(out/(name+'.stderr')).write_bytes(run.stderr)
    report['commands'].append({'name':name,'argv':argv,'exit_code':run.returncode,'elapsed_seconds':time.monotonic()-started,
                               'stdout':ident(out/(name+'.stdout')),'stderr':ident(out/(name+'.stderr'))})
    if run.returncode:report['passed']=False;break
    if name=='test':report['test']=json.loads(run.stdout)
else:report['passed']=True
(out/'RESULT.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'result':ident(out/'RESULT.json'),'passed':report['passed'],'test':report.get('test')}))
raise SystemExit(0 if report['passed'] else 1)
