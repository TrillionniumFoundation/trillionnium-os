#!/usr/bin/env python3
"""Execute production broker launch admission against synthetic Android task metadata.

No phone, Android task migration, model inference, or framework isolation claim.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys


def section(text, start, end):
    if text.count(start) != 1 or text.count(end) != 1:
        raise RuntimeError('Production extraction anchor is not unique: ' + start)
    i = text.index(start)
    return text[i:text.index(end, i)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--release8', action='store_true')
    args = parser.parse_args()
    source, out = args.source.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    pkg = source / 'src/org/trillionnium/hepta/background'
    broker = (pkg / 'BackgroundDisplayBroker.java').read_text()
    policy = pkg / 'BackgroundOwnedTaskPolicy.java'
    # Actual call-site fragment includes choose, evidence recording, gate, then setFlags.
    # The synthetic Android launch endpoint executes only after this exact fragment returns.
    admission = section(broker,
        '                    BackgroundOwnedTaskPolicy.Plan taskPolicy = BackgroundOwnedTaskPolicy.choose(',
        '                    // End unchanged standard/document admission.')
    guard = section(broker, '    private static void requireIsolatedTaskLaunch(',
        '    private JSONObject taskLaunchPolicyEvidence(')
    snapshot = section(broker, '    /** Requires the privileged whole-root list,',
        '    private void startWatchdog()')
    fixture = r"""package org.trillionnium.hepta.background;
import java.util.*;
import java.lang.reflect.Method;
/** Android IO stubs only; admission, guard and snapshot are verbatim production. */
public final class BrokerLaunchAdmissionFixture {
    static final String GENERATION="12345678-1234-1234-1234-123456789012";
    final Config config=new Config(); int displayId=6;
    final Map<String,BackgroundOwnedTaskPolicy.Plan> taskLaunchPolicies=new LinkedHashMap<String,BackgroundOwnedTaskPolicy.Plan>();
    int flagMutations, launches;
    Object activityTasks;Method allRootTasks;
    BackgroundOwnedSingleTask ownedSingleTask;
    static final class Config {final String generation=GENERATION;}
    static final class Request {final String requestId="request",packageName="test.b";}
    final class Intent {
        int flags;Intent(int value){flags=value;}int getFlags(){return flags;}
        void setFlags(int value){flags=value;flagMutations++;}
    }
    void launch(BackgroundOwnedTaskPolicy.Activity currentActivity,int flags)throws Exception {
        Request r=new Request();Intent intent=new Intent(flags);
{{admission}}
        launches++; // Synthetic Android endpoint; no real Activity is started.
    }
{{guard}}
    private BackgroundOwnedTaskPolicy.Plan taskLaunchPolicyEvidence(Request r,
            BackgroundOwnedTaskPolicy.Activity activity,BackgroundOwnedTaskPolicy.Plan plan){return plan;}
    public static final class RootInfo {
        public int displayId=0,numActivities=3;
        public boolean visible=true;
        public ComponentName baseActivity=new ComponentName("test.a",".Root"),topActivity=new ComponentName("test.c",".Top");
        public int[] childTaskIds={41};public String[] childTaskNames={"test.a/.Root"};
    }
    public static final class TaskService {
        public List<RootInfo> getAllRootTaskInfos(){return Collections.singletonList(new RootInfo());}
    }
    void demonstrateMetadataGap()throws Exception {
        activityTasks=new TaskService();allRootTasks=TaskService.class.getMethod("getAllRootTaskInfos");
        TaskSnapshot parsed=snapshot();parsed.requireNoOtherDisplay("test.b",6);
        if(parsed.rows.get(0).packages.contains("test.b"))throw new AssertionError("middle package unexpectedly present");
        boolean knownDenied=false;
        try{parsed.requireNoOtherDisplay("test.a",6);}catch(BrokerProtocol.Refusal expected){knownDenied="APP_ALREADY_ON_MAIN_DISPLAY".equals(expected.code);}
        if(!knownDenied)throw new AssertionError("visible package positive control must reject");
    }
{{snapshot}}
}
final class ComponentName {
    final String pkg,cls;ComponentName(String pkg,String cls){this.pkg=pkg;this.cls=cls;}
    String getPackageName(){return pkg;}
    static ComponentName unflattenFromString(String value){if(value==null)return null;int i=value.indexOf('/');return i<=0||i==value.length()-1?null:new ComponentName(value.substring(0,i),value.substring(i+1));}
}
final class BrokerProtocol {
    static final class Refusal extends Exception {private static final long serialVersionUID=1L;final String code;Refusal(String code){super(code);this.code=code;}}
    static boolean packageName(String value){return value!=null&&value.matches("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+");}
}
"""
    for name, piece in [('admission', admission), ('guard', guard), ('snapshot', snapshot)]:
        fixture = fixture.replace('{{' + name + '}}', piece)
    # Give each Android IO stub its own source unit so the release gate keeps
    # all lint categories enabled instead of suppressing auxiliaryclass warnings.
    package = 'package org.trillionnium.hepta.background;\n'
    main_fixture, component = fixture.split('\nfinal class ComponentName {', 1)
    component, protocol = component.split('\nfinal class BrokerProtocol {', 1)
    fixture_path = out / 'BrokerLaunchAdmissionFixture.java'
    fixture_path.write_text(main_fixture + '\n')
    component_path = out / 'ComponentName.java'
    component_path.write_text(package + 'final class ComponentName {' + component + '\n')
    protocol_path = out / 'BrokerProtocol.java'
    protocol_path.write_text(package + 'final class BrokerProtocol {' + protocol + '\n')
    test = Path(__file__).with_name('BackgroundLaunchIsolationHostTest.java')
    classes = out / 'classes'
    classes.mkdir()
    compiler = [shutil.which('javac')] if shutil.which('javac') else ['java', '-m', 'jdk.compiler/com.sun.tools.javac.Main']
    compile_command = compiler + (['--release', '8'] if args.release8 else ['-source', '8', '-target', '8']) + [
        '-encoding', 'UTF-8', '-Xlint:all' if args.release8 else '-Xlint:all,-options', '-Werror', '-d', str(classes),
        str(policy), str(pkg/'BackgroundOwnedSingleTask.java'), str(fixture_path), str(component_path), str(protocol_path), str(test)]
    records=[]
    for name, command in [('compile',compile_command),('counterexample-and-guard',['java','-cp',str(classes),'org.trillionnium.hepta.background.BackgroundLaunchIsolationHostTest'])]:
        run = subprocess.run(command,capture_output=True,text=True,timeout=60)
        (out/(name+'.stdout')).write_text(run.stdout)
        (out/(name+'.stderr')).write_text(run.stderr)
        records.append({'name':name,'exit_code':run.returncode})
        if run.returncode:
            print(run.stdout);print(run.stderr,file=sys.stderr)
            return run.returncode
    report={'schema':'hepta.background-launch-isolation-host.v1','status':'passed','stages':records,
        'source_sha256':{'BackgroundDisplayBroker.java':hashlib.sha256(broker.encode()).hexdigest(),
            'BackgroundOwnedSingleTask.java':hashlib.sha256((pkg/'BackgroundOwnedSingleTask.java').read_bytes()).hexdigest(),
            'BackgroundOwnedTaskPolicy.java':hashlib.sha256(policy.read_bytes()).hexdigest()},
        'extracted_sha256':{name:hashlib.sha256(piece.encode()).hexdigest() for name,piece in [('admission',admission),('guard',guard),('snapshot',snapshot)]},
        'compiler_contract':'Java 8 API release gate' if args.release8 else 'Java 8 source/target only; no API release claim',
        'phone_operations':False,'android_runtime':False,'task_migration_reproduced':False,
        'boundary':'Actual production broker admission/snapshot/guard and full task policy. Android task metadata, evidence serialization and launch endpoint are IO fakes. A metadata gap is demonstrated; rejected plans reach zero fake launches.'}
    (out/'RESULT.json').write_text(json.dumps(report,indent=2)+'\n')
    print((out/'counterexample-and-guard.stdout').read_text(),end='')
    print(json.dumps(report,indent=2))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
