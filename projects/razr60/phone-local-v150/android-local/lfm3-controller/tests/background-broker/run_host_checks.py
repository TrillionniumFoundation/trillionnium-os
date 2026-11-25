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
             root/'src/org/trillionnium/hepta/background/PublicPermissionControllerUi.java',
             root/'src/org/trillionnium/hepta/background/PublicOwnGroupPolicy.java',
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
    files += [root/'src/org/trillionnium/hepta/background'/(name+'.java') for name in ('ProfileIdentity','ProfileTarget')]
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
    close_fixture=root/'tests/background-broker/535-close-reply.json'
    raw=close_fixture.read_bytes()
    if hashlib.sha256(raw).hexdigest()!='251696da23360e7212b7095763f088a7d3d09414de50286f1cf9aaa86f83879f':
        raise RuntimeError('535 recorded evidence projection changed')
    close=json.loads(raw)
    if not (close['broker_exit_observed'] and close['broker_exit_code']==0 and close['eof_seen']
            and close['release_confirmed'] and close['terminal_state']=='RELEASED' and not close['custody_retained']
            and close['failure_phase']=='SCREEN_LEASE' and close['failure_category']=='PUBLIC_SCREEN_NOT_ON'
            and close['failure_at']==close['screen_released_elapsed_ms']<close['history_checked_elapsed_ms']
            and close['original_cleanup_error']=='后台响应提前结束' and not close['original_cleanup_known']):
        raise RuntimeError('535 actual ordering or historical outcome differs')
    # Extract the actual two broker methods; host ports supply the clock, socket
    # identities and independently tested cleanup latch/custody inputs.
    begin=text.index('    private boolean profileCloseReplyPending(')
    finish=text.index('    private void shutdown(String reason)',begin)
    methods=text[begin:finish]
    registration_legacy='if(config.publicOwnGroupScope!=null&&config.profileTarget!=null&&"close".equals(request.operation))'
    registration_current=('if(config.publicOwnGroupScope!=null&&(config.profileTarget!=null||publicNotesCustody!=null)\n'
                          '                                &&"close".equals(request.operation))')
    # The exact predecessor is accepted only to run the negative transport proof;
    # its real Notes pipe must fail the added case, never qualify the candidate.
    registration=registration_current if text.count(registration_current)==1 else registration_legacy
    checks=['request.authenticate(config, accepted.getPeerCredentials().getUid());',
            'request.checkDeadline(SystemClock.elapsedRealtime(), expires);',
            registration,
            'authenticatedProfileClosePeer=accepted;', 'response = perform(request);',
            'BrokerProtocol.writeFrame(accepted.getOutputStream(), response);','authenticatedProfileClosePeer=null;']
    if any(text.count(h)!=1 for h in checks) or [text.index(h) for h in checks]!=sorted(text.index(h) for h in checks):
        raise RuntimeError('original authenticated single close socket lifecycle changed')
    for fence in ('if(!profileCloseReplyPending(SystemClock.elapsedRealtime()))shutdown(code(error));',
                  'now - cleanupAt >= CLEANUP_MS && !releasedProfileReplyMayFlush(now)'):
        if text.count(fence)!=1:raise RuntimeError('normal close monitor/deadline integration changed')
    close_program=root/'tests/background-broker/BrokerCloseReplyHost.template'
    close_java=args.out/'BrokerCloseReplyHost.java'
    auth_begin=text.index('                    request.authenticate(config, accepted.getPeerCredentials().getUid());')
    auth_end=text.index('                        response = perform(request);',auth_begin)
    registration_prefix=text[auth_begin:auth_end]
    shutdown=text[text.index('    private void shutdown(String reason)'):text.index('    private void retireBootRead()')]
    socket_close=text[text.index('    private void closeSockets()'):text.index('    private byte[] response(')]
    monitor='if(!profileCloseReplyPending(SystemClock.elapsedRealtime()))shutdown(code(error));'
    replacements={'    METHODS':methods,'    SHUTDOWN_METHOD':shutdown,'    SOCKETS_METHOD':socket_close,
                  '        REGISTRATION_PREFIX':registration_prefix,'        MONITOR_CONDITION':'        '+monitor}
    generated=close_program.read_text()
    for marker,actual in replacements.items():
        if generated.count(marker)!=1:raise RuntimeError('close fixture marker changed: '+marker)
        generated=generated.replace(marker,actual)
    close_java.write_text(generated)
    files.append(close_java)

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
                'close_reply_methods_sha256': hashlib.sha256(methods.encode()).hexdigest(),
                'close_registration_prefix_sha256': hashlib.sha256(registration_prefix.encode()).hexdigest(),
                'close_shutdown_sha256': hashlib.sha256(shutdown.encode()).hexdigest(),
                'close_sockets_sha256': hashlib.sha256(socket_close.encode()).hexdigest(),
                'close_monitor_sha256': hashlib.sha256(monitor.encode()).hexdigest(),
                'close_template_sha256': hashlib.sha256(close_program.read_bytes()).hexdigest(),
                'close_reply_boundary': 'Exact production registration call order, pending/flush predicates, late-monitor branch, shutdown and socket-close bodies; authentication result, clock, cleanup and Android socket identities are explicit host ports; real BrokerProtocol framing and Java pipe effects; no Android cleanup qualification',
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
    if compile_result.returncode == 0:
        close_result=subprocess.run([str(args.java),'-cp',str(classes),'org.trillionnium.hepta.background.BrokerCloseReplyHost',
            str(close['failure_at']),str(close['history_checked_elapsed_ms'])],text=True,capture_output=True,timeout=30)
        (args.out/'close-reply.stdout').write_text(close_result.stdout)
        (args.out/'close-reply.stderr').write_text(close_result.stderr)
        evidence['close_reply_exit_code']=close_result.returncode
        evidence['close_reply_fixture_sha256']=hashlib.sha256(raw).hexdigest()
        if close_result.returncode==0:evidence['close_reply_tests']=json.loads(close_result.stdout)
    evidence['passed'] = evidence.get('compile_exit_code') == 0 and evidence.get('close_reply_exit_code') == 0 and evidence.get('run_exit_code') == 0 and evidence.get('snapshot_exit_code') == 0 and evidence.get('geometry_exit_code') == 0
    (args.out/'RESULT.json').write_text(json.dumps(evidence, ensure_ascii=False, indent=2)+'\n')
    print(json.dumps(evidence, ensure_ascii=False))
    raise SystemExit(0 if evidence['passed'] else 1)


if __name__ == '__main__':
    main()
