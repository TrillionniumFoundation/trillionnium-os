"""Compile the exact production RunHandle body; no Android, native runtime or phone."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class WarmHandleTimelineTest(unittest.TestCase):
    def test_exact_production_handle_first_wins_and_existing_call_counts(self):
        engine = (ROOT / "src/org/trillionnium/hepta/local/LocalModelEngine.java").read_text()
        start = engine.index("    public static final class RunHandle {")
        end = engine.index("    /** Retains the existing process-wide slot", start)
        production = engine[start:end]
        javac = os.environ.get("HEPTA_TEST_JAVAC") or shutil.which("javac")
        java = os.environ.get("HEPTA_TEST_JAVA") or shutil.which("java")
        self.assertTrue(javac and java, "JDK required for the exact production handle test")
        fixture = r"""
import org.trillionnium.hepta.local.WarmProcessTimeline;
import java.io.*;
import java.util.*;
import java.util.concurrent.atomic.*;
public final class RunHandleTimelineFixture {
__PRODUCTION__
    private static final String G="11111111111111111111111111111111";
    private static final String T="22222222222222222222222222222222";
    private static final String R="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static void check(boolean value,String message){if(!value)throw new AssertionError(message);}
    private static final class Child extends Process {
        boolean alive=true;int destroys;
        public OutputStream getOutputStream(){return new ByteArrayOutputStream();}
        public InputStream getInputStream(){return new ByteArrayInputStream(new byte[0]);}
        public InputStream getErrorStream(){return new ByteArrayInputStream(new byte[0]);}
        public int waitFor(){return exitValue();}
        public int exitValue(){if(alive)throw new IllegalThreadStateException();return 0;}
        public boolean isAlive(){return alive;}
        public void destroy(){destroys++;}
    }
    public static void main(String[] args){
        WarmProcessTimeline timeline=new WarmProcessTimeline(G,T);
        RunHandle owner=new RunHandle(G);owner.parentTimeline=timeline;
        RunHandle request=new RunHandle(R,owner);
        Child child=new Child();owner.child.set(child);request.child.set(child);
        request.cancel();
        Map<String,Object> first=timeline.snapshot();
        check(request.isCancellationRequested()&&owner.isCancellationRequested(),"cancel flags propagate");
        check(child.destroys==2,"baseline request plus owner calls preserved");
        check(Integer.valueOf(2).equals(first.get("destroy_invocation_count")),"both calls recorded");
        check("request_handle_cancel".equals(((Map<?,?>)first.get("first_cancel_requested")).get("source")),"request cause first-wins");
        check("owner_handle_cancel".equals(((Map<?,?>)first.get("first_destroy_invoked")).get("source")),"earliest actual owner invocation recorded");
        check(((Integer)((Map<?,?>)first.get("first_cancel_requested")).get("sequence")).intValue()
                <((Integer)((Map<?,?>)first.get("first_destroy_invoked")).get("sequence")).intValue(),"request precedes owner invocation");
        request.cancel();
        check(child.destroys==4,"repeated cancel keeps existing behavior without new calls");
        check(first.get("first_cancel_requested").equals(timeline.snapshot().get("first_cancel_requested")),"cancel timestamp stable");
        check(first.get("first_destroy_invoked").equals(timeline.snapshot().get("first_destroy_invoked")),"destroy timestamp stable");
        child.alive=false;request.cancel();owner.cancel();
        check(child.destroys==4,"already-dead child receives no extra handle call");
        check(Integer.valueOf(4).equals(timeline.snapshot().get("destroy_invocation_count")),"all actual calls counted");
        check(timeline.snapshot().get("first_exit_observed")==null,"handle liveness check does not invent wait/exit evidence");
        check(G.equals(first.get("worker_generation"))&&T.equals(first.get("task_id")),"shared task identity");
        WarmProcessTimeline beforeLaunch=new WarmProcessTimeline(G,T);
        RunHandle prelaunch=new RunHandle(G);prelaunch.parentTimeline=beforeLaunch;prelaunch.cancel();
        check(prelaunch.isCancellationRequested(),"prelaunch cancellation retained");
        check(beforeLaunch.snapshot().get("first_destroy_invoked")==null,"no process means no destroy invocation");
        RunHandle legacy=new RunHandle();Child oldChild=new Child();legacy.child.set(oldChild);legacy.cancel();
        check(oldChild.destroys==1&&legacy.isCancellationRequested(),"one-shot handle behavior unchanged");
        System.out.println("production RunHandle cancellation paths PASS; synthetic Process only");
    }
}
"""
        fixture = fixture.replace("__PRODUCTION__", production)
        with tempfile.TemporaryDirectory(prefix="hepta-handle-timeline-") as directory:
            directory = Path(directory)
            source = directory / "RunHandleTimelineFixture.java"
            source.write_text(fixture)
            compile_result = subprocess.run(
                [javac, "--release", "8", "-encoding", "UTF-8", "-Xlint:all", "-Werror",
                 "-d", str(directory), str(ROOT / "src/org/trillionnium/hepta/local/WarmProcessTimeline.java"),
                 str(source)], capture_output=True, text=True, timeout=60)
            self.assertEqual(compile_result.returncode, 0, compile_result.stdout + compile_result.stderr)
            result = subprocess.run([java, "-cp", str(directory), "RunHandleTimelineFixture"],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("cancellation paths PASS", result.stdout)
            print("RunHandle exact production SHA-256:", hashlib.sha256(production.encode()).hexdigest())


if __name__ == "__main__":
    unittest.main()
