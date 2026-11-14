#!/usr/bin/env python3
"""Compile and execute the actual pure-Java protocol guard; never contacts Android."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java', required=True, type=Path)
    parser.add_argument('--javac', type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--development-platform-only', action='store_true',
                        help='Use current JDK platform, explicitly NOT the Java 8 release gate')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    classes = args.out / 'classes'
    classes.mkdir()
    root = Path(__file__).resolve().parents[2]
    files = [root/'src/org/trillionnium/hepta/background/BrokerProtocol.java',
             root/'tests/background-broker/BrokerProtocolHostTest.java']
    # Compile the exact production whole-root snapshot and its policy, with only Android IO fields faked.
    broker = root/'src/org/trillionnium/hepta/background/BackgroundDisplayBroker.java'
    text = broker.read_text()
    start = '    private TaskSnapshot snapshot() throws Exception {'
    end = '    private void startWatchdog() {'
    if text.count(start) != 1 or text.count(end) != 1:
        raise RuntimeError('production snapshot anchors changed')
    part = text[text.index(start):text.index(end)]
    fixture = args.out/'BrokerTaskSnapshotFixture.java'
    fixture.write_text('''package org.trillionnium.hepta.background;
import android.content.ComponentName;import java.lang.reflect.Method;import java.util.*;
final class BrokerTaskSnapshotFixture {
 private final Object activityTasks;private final Method allRootTasks;
 private final BackgroundOwnedSingleTask ownedSingleTask=null; // Legacy fixture has no owned launch.
 BrokerTaskSnapshotFixture(Object tasks)throws Exception{activityTasks=tasks;allRootTasks=tasks.getClass().getMethod("getAllRootTaskInfos");}
 void requireNoOtherDisplay(String pkg,int display)throws Exception{snapshot().requireNoOtherDisplay(pkg,display);}
''' + part + '}\n')
    component = args.out/'ComponentName.java'
    component.write_text('''package android.content;
public final class ComponentName {
 private final String pkg,cls;
 public ComponentName(String pkg,String cls){this.pkg=pkg;this.cls=cls;}
 public String getPackageName(){return pkg;}
 public static ComponentName unflattenFromString(String value){int at=value.indexOf('/');if(at<0||at+1>=value.length())return null;String pkg=value.substring(0,at),cls=value.substring(at+1);return new ComponentName(pkg,cls.startsWith(".")?pkg+cls:cls);}
}
''')
    files += [fixture,component,root/'tests/background-broker/BrokerTaskSnapshotHostTest.java']
    files.append(root/'src/org/trillionnium/hepta/background/FixedIntentTools.java')
    files += [root/'src/org/trillionnium/hepta/background/BackgroundOwnedSingleTask.java',
              root/'src/org/trillionnium/hepta/background/BackgroundOwnedTaskPolicy.java']
    geometry_start = '    static final class DisplayGeometry {'
    geometry_end = '    private void ensureNameAbsent() throws BrokerProtocol.Refusal {'
    if text.count(geometry_start) != 1 or text.count(geometry_end) != 1:
        raise RuntimeError('production display geometry anchors changed')
    geometry_part = text[text.index(geometry_start):text.index(geometry_end)]
    geometry = args.out/'BrokerDisplayGeometryFixture.java'
    geometry.write_text('''package org.trillionnium.hepta.background;
import android.hardware.display.DisplayManager;import android.view.Display;
import android.util.DisplayMetrics;import android.os.SystemClock;
final class BrokerDisplayGeometryFixture {
''' + geometry_part + '}\n')
    metrics = args.out/'DisplayMetrics.java'
    metrics.write_text('''package android.util;
public final class DisplayMetrics { public int widthPixels,heightPixels,densityDpi; }
''')
    clock = args.out/'SystemClock.java'
    clock.write_text('''package android.os;
public final class SystemClock {
 public static long now=100,step=1;
 private SystemClock(){}
 public static long elapsedRealtime(){long value=now;now+=step;return value;}
}
''')
    display = args.out/'Display.java'
    display.write_text('''package android.view;
public final class Display {
 public static final int DEFAULT_DISPLAY=0;
 public int id,width,height,density,rotation;public String name;public boolean valid=true;
 public Runnable afterMetrics;
 public Display(int id,String name,int width,int height,int density,int rotation){
  this.id=id;this.name=name;this.width=width;this.height=height;this.density=density;this.rotation=rotation;
 }
 public int getDisplayId(){return id;} public boolean isValid(){return valid;}
 public String getName(){return name;} public int getRotation(){return rotation;}
 @Deprecated public void getRealMetrics(android.util.DisplayMetrics out){
  out.widthPixels=width;out.heightPixels=height;out.densityDpi=density;
  if(afterMetrics!=null)afterMetrics.run();
 }
 public Object getMode(){throw new AssertionError("physical mode must not supply logical geometry");}
}
''')
    display_manager = args.out/'DisplayManager.java'
    display_manager.write_text('''package android.hardware.display;
import android.view.Display;import java.util.*;
public final class DisplayManager {
 private final Display first,second,cover;private int defaultReads;
 public final List<Integer> requested=new ArrayList<Integer>();
 public DisplayManager(Display first,Display second,Display cover){this.first=first;this.second=second;this.cover=cover;}
 public Display getDisplay(int id){requested.add(id);if(id==0)return defaultReads++==0?first:second;if(id==1)return cover;return null;}
 public Display[] getDisplays(){throw new AssertionError("display enumeration must not select geometry");}
}
''')
    files += [geometry,metrics,clock,display,display_manager]
    compiler = [str(args.javac)] if args.javac else [str(args.java), '-m', 'jdk.compiler/com.sun.tools.javac.Main']
    flags = [] if args.development_platform_only else ['--release', '8']
    compile_argv = compiler + flags + ['-Xlint:all', '-Werror', '-encoding', 'UTF-8', '-d', str(classes)] + list(map(str, files))
    compile_result = subprocess.run(compile_argv, text=True, capture_output=True, timeout=60)
    (args.out/'compile.stdout').write_text(compile_result.stdout)
    (args.out/'compile.stderr').write_text(compile_result.stderr)
    evidence = {'schema': 'hepta.background-broker-host-run.v1', 'android_runtime': False,
                'phone_operations': False, 'source_files': {str(f): hashlib.sha256(f.read_bytes()).hexdigest() for f in files},
                'broker_sha256': hashlib.sha256(broker.read_bytes()).hexdigest(),
                'snapshot_sha256': hashlib.sha256(part.encode()).hexdigest(),
                'snapshot_boundary': 'Exact production method/row policy; Android ComponentName and RootTaskInfo fields are controlled host fixtures',
                'geometry_sha256': hashlib.sha256(geometry_part.encode()).hexdigest(),
                'geometry_boundary': 'Exact production nested class; Display/DisplayManager logical metrics and elapsedRealtime are explicit host IO fixtures, not Android rendering qualification',
                'java8_release_gate': not args.development_platform_only,
                'development_platform_only': args.development_platform_only,
                'compile_argv': compile_argv, 'compile_exit_code': compile_result.returncode}
    if compile_result.returncode == 0:
        run_argv = [str(args.java), '-cp', str(classes), 'org.trillionnium.hepta.background.BrokerProtocolHostTest']
        run_result = subprocess.run(run_argv, text=True, capture_output=True, timeout=30)
        (args.out/'run.stdout').write_text(run_result.stdout)
        (args.out/'run.stderr').write_text(run_result.stderr)
        evidence['run_exit_code'] = run_result.returncode
        if run_result.returncode == 0:
            evidence['tests'] = json.loads(run_result.stdout)
        else:
            evidence['run_error'] = run_result.stderr
    if compile_result.returncode == 0:
        snapshot_result = subprocess.run([str(args.java), '-cp', str(classes), 'org.trillionnium.hepta.background.BrokerTaskSnapshotHostTest'], text=True, capture_output=True, timeout=30)
        (args.out/'snapshot.stdout').write_text(snapshot_result.stdout)
        (args.out/'snapshot.stderr').write_text(snapshot_result.stderr)
        evidence['snapshot_exit_code'] = snapshot_result.returncode
        if snapshot_result.returncode == 0:
            evidence['snapshot_tests'] = json.loads(snapshot_result.stdout)
    if compile_result.returncode == 0:
        geometry_result = subprocess.run([str(args.java), '-cp', str(classes), 'org.trillionnium.hepta.background.BrokerDisplayGeometryHostTest'], text=True, capture_output=True, timeout=30)
        (args.out/'geometry.stdout').write_text(geometry_result.stdout)
        (args.out/'geometry.stderr').write_text(geometry_result.stderr)
        evidence['geometry_exit_code'] = geometry_result.returncode
        if geometry_result.returncode == 0:
            evidence['geometry_tests'] = json.loads(geometry_result.stdout)
    evidence['passed'] = evidence.get('compile_exit_code') == 0 and evidence.get('run_exit_code') == 0 and evidence.get('snapshot_exit_code') == 0 and evidence.get('geometry_exit_code') == 0
    (args.out/'RESULT.json').write_text(json.dumps(evidence, ensure_ascii=False, indent=2)+'\n')
    print(json.dumps(evidence, ensure_ascii=False))
    raise SystemExit(0 if evidence['passed'] else 1)


if __name__ == '__main__':
    main()
