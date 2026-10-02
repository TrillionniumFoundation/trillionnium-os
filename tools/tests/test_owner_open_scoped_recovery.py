from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/owner-open"))
from owner_open_broker_client import expected_for
from owner_open_broker_mux import ordering_key_for_frame

FRAME = ROOT / "android-integration/working-tree/vendor/trillionnium/owner-open/client/src/org/trillionnium/owneropen/OwnerOpenFrame.java"


class ScopedRecoveryTest(unittest.TestCase):
    def test_flow_controls_have_finite_turn_scoped_broker_routes(self):
        scope = dict(session_id="session", profile_id="profile", task_id="task", turn_id="turn", turn_stream_id="stream")
        expected_key = ordering_key_for_frame({"kind": "turn.inspect", "payload": scope}, "client-a")
        for kind in ("stream.pause", "stream.resume", "stream.window_update"):
            frame = {"kind": kind, "payload": scope}
            self.assertEqual(expected_for(frame), ([kind + ".ack"], None))
            self.assertEqual(ordering_key_for_frame(frame, "client-b"), expected_key)

    def test_android_plan_inspects_each_scope_and_rejects_uncertain_prefix(self):
        compiler, java = shutil.which("javac"), shutil.which("java")
        if not compiler or not java:
            self.skipTest("JDK required for executable Android recovery codec")
        harness = textwrap.dedent(r'''
            import java.util.*;
            import org.trillionnium.owneropen.OwnerOpenFrame;
            public final class RecoveryHarness {
                static Map<String,Object> scope(String job) {
                    Map<String,Object> m = new LinkedHashMap<>();
                    m.put("session_id","session"); m.put("profile_id","profile");
                    m.put("task_id","task"); m.put("turn_id","turn"); m.put("turn_stream_id","stream");
                    if(job != null) m.put("job_id",job);
                    return m;
                }
                static Map<String,Object> range(String domain,String job,long first,long last) {
                    return Map.of("cursor_domain",domain,"cursor_scope",scope(job),
                        "first_missing_cursor",first,"last_missing_cursor",last,"required_resume_cursor",last+1);
                }
                static OwnerOpenFrame.RecoveryPlan plan(List<?> ranges) {
                    Map<String,Object> f=scope(null);
                    f.put("payload",Map.of("resync_protocol","scoped_cursor_v1","cursor_scopes_complete",true,"required_resumes",ranges));
                    return new OwnerOpenFrame.RecoveryPlan(f,Map.of("resync_protocols",List.of("scoped_cursor_v1")),"a".repeat(64));
                }
                static Map<String,Object> response(String job,String kind,Map<String,Object> payload) {
                    Map<String,Object> f=scope(job); f.put("kind",kind); f.put("payload",payload); return f;
                }
                static Map<String,Object> payload() {
                    Map<String,Object> p=new LinkedHashMap<>();p.put("status","found");
                    p.put("side_effects",false);p.put("automatic_redispatch",false);return p;
                }
                static Map<String,Object> turn(long first,long next) {
                    Map<String,Object> p=payload(); p.put("source","durable_event_store");
                    p.put("inclusive_cursor",first);p.put("next_cursor",next);
                    List<Object> frames=new ArrayList<>();
                    for(long i=first;i<next;i++)frames.add(Map.of("event_id","stream-event-"+i));
                    p.put("frames",frames);return response(null,"turn.inspect.result",p);
                }
                static Map<String,Object> job(String job,long first,long next,boolean gap) {
                    Map<String,Object> p=payload();p.put("runtime_cursor_domain","job_runtime_event");
                    Map<String,Object> i=new LinkedHashMap<>();i.put("inclusive_cursor",first);i.put("next_cursor",next);
                    i.put("oldest_available_cursor",first);i.put("resync_required",gap);i.put("gap",gap?Map.of("first_missing_cursor",first):null);
                    List<Object> events=new ArrayList<>();for(long n=first;n<next;n++)events.add(Map.of("seq",n));
                    i.put("runtime_events",events);i.put("event_log_status","durable");p.put("inspection",i);
                    p.put("durable_cursor_domain","job_journal_record");p.put("durable_inclusive_cursor",first);
                    p.put("durable_next_cursor",next);
                    List<Object> journal=new ArrayList<>();for(long n=first;n<next;n++)journal.add(Map.of("job_record_seq",n));
                    p.put("durable_records",journal);
                    return response(job,"job.inspect.result",p);
                }
                static void reject(Runnable r) {try{r.run();throw new AssertionError("unsafe recovery accepted");}catch(IllegalArgumentException expected){}}
                static void require(boolean b) {if(!b)throw new AssertionError("recovery assertion failed");}
                public static void main(String[] ignored) {
                    OwnerOpenFrame.RecoveryPlan p=plan(List.of(range("transport_event",null,3,4),
                        range("job_runtime_event","job-a",4,5),range("job_journal_record","job-a",0,1)));
                    reject(()->p.resume(1));
                    require(p.nextInspection().contains("\"inclusive_cursor\":3"));
                    require(p.observeInspection(turn(3,4)));require(!p.isComplete());
                    require(p.nextInspection().contains("\"inclusive_cursor\":4"));
                    require(p.observeInspection(turn(4,5)));
                    require(p.nextInspection().contains("\"job_id\":\"job-a\""));
                    require(!p.observeInspection(job("job-b",4,5,false)));
                    require(p.observeInspection(job("job-a",4,5,false)));
                    p.nextInspection();require(p.observeInspection(job("job-a",5,6,false)));
                    require(p.nextInspection().contains("\"durable_inclusive_cursor\":0"));
                    require(p.observeInspection(job("job-a",0,1,true))); // runtime retention does not substitute for journal domain
                    p.nextInspection();require(p.observeInspection(job("job-a",1,2,true)));
                    require(p.isComplete());System.out.println(p.resume(1));
                    OwnerOpenFrame.RecoveryPlan retained=plan(List.of(range("job_runtime_event","job-a",4,5)));
                    retained.nextInspection();reject(()->retained.observeInspection(job("job-a",4,6,true)));
                    reject(()->retained.resume(1));
                    OwnerOpenFrame.RecoveryPlan skipped=plan(List.of(range("transport_event",null,3,4)));
                    skipped.nextInspection();reject(()->skipped.observeInspection(turn(4,5)));
                    reject(()->skipped.resume(1));
                    OwnerOpenFrame.RecoveryPlan stale=plan(List.of(range("transport_event",null,3,4)));
                    stale.nextInspection();Map<String,Object> wrong=turn(3,5);wrong.put("task_id","other-task");
                    require(!stale.observeInspection(wrong));reject(()->stale.resume(1));
                }
            }
        ''')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "RecoveryHarness.java"
            source.write_text(harness)
            compiled = subprocess.run([compiler, "-d", str(root), str(FRAME), str(source)], capture_output=True, text=True, timeout=30)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            executed = subprocess.run([java, "-cp", str(root), "RecoveryHarness"], capture_output=True, text=True, timeout=30)
            self.assertEqual(executed.returncode, 0, executed.stderr)
            frame = json.loads(executed.stdout)
            self.assertEqual(frame["kind"], "stream.resume")
            self.assertEqual(frame["payload"]["resync_protocol"], "scoped_cursor_v1")
            cursors = frame["payload"]["resumed_cursors"]
            self.assertEqual([(c["cursor_domain"], c["cursor_scope"].get("job_id"), c["resumed_through_cursor"]) for c in cursors],
                             [("transport_event", None, 5), ("job_runtime_event", "job-a", 6), ("job_journal_record", "job-a", 2)])


if __name__ == "__main__":
    unittest.main()
