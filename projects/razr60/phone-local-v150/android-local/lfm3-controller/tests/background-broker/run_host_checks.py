#!/usr/bin/env python3
"""Compile and execute the actual pure-Java protocol guard; never contacts Android."""
import argparse
import importlib.util
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
    # Historical source contracts use an exact whole-file proof copy. All
    # fragments below are still extracted from current production text.
    phase_helper=root/'tests/profile-cleanup-settle/protected_cleanup_phase.py'
    phase_data=phase_helper.with_name('production-predecessor.json')
    if hashlib.sha256(phase_helper.read_bytes()).hexdigest()!='a48c11798f672654823b2cf6dd9f19d31d7ea1a20f1d69b488eb1a4e4019a8d2':
        raise RuntimeError('fixed cleanup phase predecessor helper required')
    spec=importlib.util.spec_from_file_location('broker_cleanup_phase_predecessor',phase_helper)
    phase=importlib.util.module_from_spec(spec);spec.loader.exec_module(phase)
    proof_text=phase.predecessor('src/org/trillionnium/hepta/background/BackgroundDisplayBroker.java',broker.read_bytes()).decode('utf-8')
    # These legacy cases intentionally have no active normal-profile phase.
    # A mistakenly reached phase port fails; the separate settle gate compiles
    # the actual phase implementation, including its races and effect guards.
    inactive_phase_ports='''    private final ProfileOwnedTask.CleanupPhase normalProfileCleanup=null;
    private static final class ProfileOwnedTask {
        private static final class CleanupPhase {
            private CleanupPhase(){throw new AssertionError("legacy fixture cannot create cleanup phase");}
            boolean mayAwait(long now){throw new AssertionError("inactive cleanup phase reached");}
            long watchdogDeadline(){throw new AssertionError("inactive cleanup phase reached");}
        }
    }
'''
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
    # Extract the actual broker deadline/close methods; host ports supply the clock, socket
    # identities and independently tested cleanup latch/custody inputs.
    begin=text.index('    private long cleanupWatchdogDeadline(')
    finish=text.index('    private void shutdown(String reason)',begin)
    methods=text[begin:finish]
    checks=['request.authenticate(config, accepted.getPeerCredentials().getUid());',
            'request.checkDeadline(SystemClock.elapsedRealtime(), expires);',
            'if(config.publicOwnGroupScope!=null&&(config.profileTarget!=null||publicNotesCustody!=null)&&"close".equals(request.operation))',
            'authenticatedProfileClosePeer=accepted;', 'response = perform(request);',
            'BrokerProtocol.writeFrame(accepted.getOutputStream(), response);','authenticatedProfileClosePeer=null;']
    if any(text.count(h)!=1 for h in checks) or [text.index(h) for h in checks]!=sorted(text.index(h) for h in checks):
        raise RuntimeError('original authenticated single close socket lifecycle changed')
    for fence in ('if(!profileCloseReplyPending(SystemClock.elapsedRealtime()))shutdown(code(error));',
                  'now - cleanupAt >= CLEANUP_MS && !releasedProfileReplyMayFlush(now)'):
        if proof_text.count(fence)!=1:raise RuntimeError('historical normal close monitor/deadline integration changed')
    for fence in ('if(!profileCloseReplyPending(SystemClock.elapsedRealtime()))shutdown(code(error));',
                  'now >= cleanupWatchdogDeadline() && !releasedProfileReplyMayFlush(now)'):
        if text.count(fence)!=1:raise RuntimeError('actual normal close monitor/deadline integration changed')
    close_program=root/'tests/background-broker/BrokerCloseReplyHost.template'
    close_java=args.out/'BrokerCloseReplyHost.java'
    close_source=close_program.read_text()
    phase_anchor='    private static final long CLEANUP_MS=1500;\n'
    if close_source.count(phase_anchor)!=1 or close_source.count('    METHODS')!=1:
        raise RuntimeError('legacy close fixture insertion anchors changed')
    close_java.write_text(close_source.replace(phase_anchor,phase_anchor+inactive_phase_ports).replace('    METHODS',methods))
    files.append(close_java)

    # Notes close registration regression: execute the actual authenticated
    # admission block, late policy thread and original cleanup watchdog branch.
    # The parent control is a byte-exact inverse of only the reviewed two lines.
    current_registration = 'if(config.publicOwnGroupScope!=null&&(config.profileTarget!=null||publicNotesCustody!=null)&&"close".equals(request.operation))'
    parent_registration = 'if(config.publicOwnGroupScope!=null&&config.profileTarget!=null&&"close".equals(request.operation))'
    current_comment = '// Only an authenticated, already admitted profile or personal Notes close RPC owns this peer.'
    parent_comment = '// Only the authenticated, already admitted work-profile close RPC can own this peer.'
    if text.count(current_registration)!=1 or text.count(current_comment)!=1:
        raise RuntimeError('exact reviewed Notes close registration required')
    parent_text=text.replace(current_registration,parent_registration).replace(current_comment,parent_comment)
    parent_proof_text=proof_text.replace(current_registration,parent_registration).replace(current_comment,parent_comment)
    if hashlib.sha256(parent_proof_text.encode()).hexdigest()!='a74cd6c88a4468631c8e3d2f70fab7e1a6e7d66a6749cfc0c98742456a3f6f44':
        raise RuntimeError('two-line inverse must equal complete recorded parent Broker')
    def exact_slice(value,first,last):
        if value.count(first)!=1 or value.count(last)!=1:
            raise RuntimeError('Notes close source extraction anchors changed')
        begin=value.index(first)
        finish=value.index(last,begin)
        return value[begin:finish]
    admission_first='                BrokerProtocol.Request request = null;\n'
    admission_last='                if(config.publicOwnGroupScope!=null&&(closing.get()||publicAdmissionRetired.get())\n'
    policy_first='        Thread locks = new Thread(() -> {\n'
    policy_end='        locks.setDaemon(true); locks.start();\n'
    policy_part=text[text.index(policy_first):text.index(policy_end)+len(policy_end)]
    if text.count(policy_first)!=1 or text.count(policy_end)!=1:
        raise RuntimeError('actual late policy thread must be unique')
    cleanup_part=exact_slice(text,
        '                if (cleanupStarted.get() && now >= cleanupWatchdogDeadline() && !releasedProfileReplyMayFlush(now)) {\n',
        '                if (!closing.get()) {\n')
    perform_start='    private byte[] perform(BrokerProtocol.Request r) throws Exception {\n'
    if text.count(perform_start)!=1:raise RuntimeError('actual perform method must be unique')
    perform_at=text.index(perform_start)
    guard_anchor='            guard(r, false);\n'
    perform_prefix=text[perform_at:text.index(guard_anchor,perform_at)+len(guard_anchor)]
    close_part=exact_slice(perform_prefix,'            if ("close".equals(r.operation)) {\n',guard_anchor)
    shutdown_part=exact_slice(text,'    private void shutdown(String reason) {\n','    private void retireBootRead() {\n')
    finally_first='                try { accepted.close(); } catch (IOException ignored) {}\n'
    finally_last='                connection = null; requestDeadline = 0; connectionDeadline = 0;activeRequestPeerPid=-1;\n'
    finally_part=text[text.index(finally_first):text.index(finally_last)+len(finally_last)]
    constants=[line for line in text.splitlines() if line.startswith('    private static final long STARTUP_MS = ')]
    if len(constants)!=1:raise RuntimeError('actual broker deadline constants required')
    replacements={
        '    CONSTANTS':constants[0],
        '                UID_GATE':'                if (accepted.getPeerCredentials().getUid() != config.ownerUid) continue;',
        '                CURRENT_ADMISSION':exact_slice(text,admission_first,admission_last).rstrip(),
        '                PARENT_ADMISSION':exact_slice(parent_text,admission_first,admission_last).rstrip(),
        '                FRAME_WRITE':'                BrokerProtocol.writeFrame(accepted.getOutputStream(), response);',
        '                PEER_FINALLY':finally_part.rstrip(),
        '            CLOSE_PERFORM':close_part.rstrip(),
        '            POLICY_MONITOR':policy_part.rstrip(),
        '        SHUTDOWN':shutdown_part.rstrip(),
        '        CLOSE_METHODS':methods.rstrip(),
        '            WATCHDOG_CLEANUP':cleanup_part.rstrip()
    }
    notes_template=root/'tests/background-broker/BrokerNotesCloseReplyHost.template'
    generated=notes_template.read_text()
    notes_phase_anchor='        final BrokerProtocol.Config config;\n'
    if generated.count(notes_phase_anchor)!=1:raise RuntimeError('legacy Notes fixture phase insertion anchor changed')
    generated=generated.replace(notes_phase_anchor,inactive_phase_ports+notes_phase_anchor)
    for marker,replacement_fragment in replacements.items():
        expected=2 if marker.endswith('UID_GATE') or marker.endswith('FRAME_WRITE') else 1
        if generated.count(marker)!=expected:raise RuntimeError('host marker cardinality '+marker)
        generated=generated.replace(marker,replacement_fragment)
    notes_java=args.out/'BrokerNotesCloseReplyHost.java'
    notes_java.write_text(generated)
    files.append(notes_java)
    extraction={
        'schema':'hepta.notes-close-reply-source-extraction.v1',
        'candidate_broker':{'path':str(broker),'bytes':broker.stat().st_size,'sha256':hashlib.sha256(broker.read_bytes()).hexdigest()},
        'parent_broker_inverse_sha256':hashlib.sha256(parent_proof_text.encode()).hexdigest(),
        'historical_projection_compiled':False,
        'current_broker_fragments_compiled':True,
        'normal_profile_phase_scope':'absent in these legacy cases; exact active implementation exercised by profile-cleanup-settle',
        'inactive_phase_ports_sha256':hashlib.sha256(inactive_phase_ports.encode()).hexdigest(),
        'cleanup_phase_proof_inputs':{str(p):{'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in (phase_helper,phase_data)},
        'template':{'path':str(notes_template),'bytes':notes_template.stat().st_size,'sha256':hashlib.sha256(notes_template.read_bytes()).hexdigest()},
        'actual_fragments':{key.strip():{'bytes':len(value.encode()),'sha256':hashlib.sha256(value.encode()).hexdigest()} for key,value in replacements.items()},
        'compiled_protocol':{'path':str(files[0]),'bytes':files[0].stat().st_size,'sha256':hashlib.sha256(files[0].read_bytes()).hexdigest()},
        'ports':['synthetic elapsedRealtime','host peer credentials and in-memory framed pipe','controlled cleanup/custody completion','recording halt/quarantine ports; never Runtime.halt'],
        'qualification_boundary':'Executes real source decisions and protocol framing; does not prove phone release, actual current absence or a production recovery commit.',
        'phone_operations':0
    }
    (args.out/'NOTES-CLOSE-SOURCE-EXTRACTION.json').write_text(json.dumps(extraction,ensure_ascii=False,indent=2)+'\n')

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
    if compile_result.returncode == 0:
        close_result=subprocess.run([str(args.java),'-cp',str(classes),'org.trillionnium.hepta.background.BrokerCloseReplyHost',
            str(close['failure_at']),str(close['history_checked_elapsed_ms'])],text=True,capture_output=True,timeout=30)
        (args.out/'close-reply.stdout').write_text(close_result.stdout)
        (args.out/'close-reply.stderr').write_text(close_result.stderr)
        evidence['close_reply_exit_code']=close_result.returncode
        evidence['close_reply_fixture_sha256']=hashlib.sha256(raw).hexdigest()
        if close_result.returncode==0:evidence['close_reply_tests']=json.loads(close_result.stdout)

    if compile_result.returncode == 0:
        notes_argv=[str(args.java),'-cp',str(classes),'org.trillionnium.hepta.background.BrokerNotesCloseReplyHost']
        notes_result=subprocess.run(notes_argv,text=True,capture_output=True,timeout=30)
        (args.out/'notes-close-reply.stdout').write_text(notes_result.stdout)
        (args.out/'notes-close-reply.stderr').write_text(notes_result.stderr)
        evidence['notes_close_reply_argv']=notes_argv
        evidence['notes_close_reply_exit_code']=notes_result.returncode
        evidence['notes_close_source_extraction']=extraction
        evidence['notes_close_input_files']={str(p):{'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in
            (Path(__file__).resolve(),notes_template,close_program,broker,close_fixture,phase_helper,phase_data)}
        evidence['tools']={str(p):{'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in
            ((args.java,args.javac) if args.javac else (args.java,))}
        evidence['expected_notes_close_cases']=['notes_authenticated_close_late_policy_keeps_complete_original_frame', 'parent_registration_same_notes_race_reproduces_eof', 'late_policy_wrong_current_peer_not_protected', 'late_policy_missing_notes_and_profile_custody_not_protected', 'late_policy_no_public_scope_not_protected', 'late_policy_at_original_request_deadline_not_protected', 'wrong_peer_uid_never_parses_or_registers', 'foreign_generation_never_registers', 'foreign_scope_never_registers', 'expired_request_never_registers', 'request_above_original_limit_never_registers', 'authenticated_nonclose_does_not_register_or_begin_cleanup', 'notes_cleanup_at_1499_may_flush', 'notes_cleanup_at_1500_halts_without_profile_extension', 'notes_cleanup_at_2249_still_halts', 'notes_unknown_cleanup_at_1500_is_not_success', 'profile_verified_release_at_1500_retains_original_exception', 'profile_verified_release_at_2249_may_flush', 'profile_verified_release_at_2250_halts', 'profile_exception_stops_at_original_request_deadline', 'shorter_close_request_keeps_original_wait_budget', 'session_expiry_bounds_pending_close_peer']
        if notes_result.returncode==0:
            actual=json.loads(notes_result.stdout)
            evidence['notes_close_reply_tests']=actual
            evidence['notes_close_exact_cases']=actual.get('case_names')==evidence['expected_notes_close_cases'] and actual.get('cases')==len(evidence['expected_notes_close_cases']) and actual.get('all_pass') is True
    evidence['passed'] = evidence.get('compile_exit_code') == 0 and evidence.get('close_reply_exit_code') == 0 and evidence.get('run_exit_code') == 0 and evidence.get('snapshot_exit_code') == 0 and evidence.get('geometry_exit_code') == 0 and evidence.get('notes_close_reply_exit_code') == 0 and evidence.get('notes_close_exact_cases') is True
    (args.out/'RESULT.json').write_text(json.dumps(evidence, ensure_ascii=False, indent=2)+'\n')
    print(json.dumps(evidence, ensure_ascii=False))
    raise SystemExit(0 if evidence['passed'] else 1)


if __name__ == '__main__':
    main()
