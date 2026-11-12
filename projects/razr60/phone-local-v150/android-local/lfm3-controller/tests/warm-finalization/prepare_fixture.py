"""Compile exact production Stop and close-result decisions with explicit IO fixtures."""
import hashlib
import json
from pathlib import Path


def section(text, start, end):
    if text.count(start) != 1 or text.count(end) != 1:
        raise RuntimeError("production finalization anchors are not unique")
    first = text.index(start)
    return text[first:text.index(end, first)]


def prepare(source, output):
    source = Path(source)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    package = source / "src/org/trillionnium/hepta/local"
    controller = (package / "LocalTaskController.java").read_text(encoding="utf-8")
    inference = (package / "LocalInference.java").read_text(encoding="utf-8")
    service = (package / "HeptaAccessibilityService.java").read_text(encoding="utf-8")
    parts = {
        "stop": section(controller, "    public void stop(){", "    @Override public synchronized void close()"),
        "close_result": section(controller, "            LocalInference.TaskCleanup modelCleanup;", "            if(completionInstalled!=null)try{completionInstalled.verify(service);}catch(Exception changed){\n"),
        "cleanup_contract": section(inference, "    final class TaskCleanup {", "    interface Handle {"),
        "handle_contract": section(inference, "    interface Handle {", "    interface Callback {"),
        "message_helpers": section(service, "    static String limited(", "\n}"),
    }
    local_inference = (
        "package org.trillionnium.hepta.local;\n"
        "public interface LocalInference {\n"
        + parts["cleanup_contract"]
        + parts["handle_contract"]
        + "void cancelTask();\nTaskCleanup endTask();\n}\n"
    )
    fixture = """package org.trillionnium.hepta.local;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
public final class ControllerFinalizationFixture {
    private final LocalInference inference;
    private final AtomicBoolean cancelled=new AtomicBoolean();
    private final Object handleLock=new Object();
    private volatile boolean running=true,blocked;
    private LocalInference.Handle activeInference;
    private final String currentTaskId="33333333333333333333333333333333";
    private final AtomicLong stopRequestedElapsed=new AtomicLong(-1);
    private final CancellationServiceFixture service=new CancellationServiceFixture(currentTaskId);
    private final TaskCancellationQueue.Ticket taskCancellation=new TaskCancellationQueue.Ticket(service,currentTaskId);
    /** Explicit service/clock IO seams; the queue, Stop and terminal decisions remain production code. */
    private static final class SystemClock { static long elapsedRealtime(){return System.nanoTime()/1000000L;} }
    private static final class CancellationServiceFixture {
        private final String taskId;
        private final TaskCancellationQueue queue=new TaskCancellationQueue(new java.util.concurrent.Executor(){
            public void execute(Runnable work){
                Thread worker=new Thread(work,"fixture-native-cancel");worker.setDaemon(true);worker.start();
            }
        });
        CancellationServiceFixture(String taskId){this.taskId=taskId;}
        void retireActionWork(String task,String reason){
            if(!taskId.equals(task)||!"cancelled".equals(reason))throw new AssertionError("wrong captured action task");
        }
        void requestNativeCancellation(TaskCancellationQueue.Ticket ticket,Runnable signal){
            if(!ticket.ownedBy(this)||!taskId.equals(ticket.taskId))throw new AssertionError("wrong captured native task");
            queue.request(ticket,new TaskCancellationQueue.Lease(){
                public boolean current(String task){return taskId.equals(task);}
            },signal);
        }
        boolean nativeCancellationWorkPending(){return queue.pending();}
    }
    /** Test scheduling barrier only: no fake drain, no sleep, and never called inside the extracted Stop. */
    public void awaitCancellation()throws InterruptedException{
        if(!taskCancellation.awaitDrain(2000))throw new AssertionError("real cancellation worker did not drain");
    }
    /** Scope/config IO seam; default absent preserves all original 13 cases. */
    public interface ScopeCheck { void verifyUnchanged() throws Exception; }
    private ScopeCheck scope;
    /** Admitted/live Owner authorization seam; actual admission runs in the controller harness. */
    private interface AuthorizationFrame { boolean successAllowed(); }
    private interface AuthorizationCheck { void ready(); AuthorizationFrame frame(); }
    private final AuthorizationCheck authorization=new AuthorizationCheck(){
        public void ready(){}
        public AuthorizationFrame frame(){throw new AssertionError("legacy fixture has no controller-workflow candidate");}
    };
    public void setScopeCheck(ScopeCheck check){scope=check;}
    private void emitForTask(String task,String value) {
        if(!currentTaskId.equals(task))throw new AssertionError("wrong listener task");
        /* Android listener fixture; no IO. */
    }
    public ControllerFinalizationFixture(LocalInference inference){this.inference=inference;}
    public static final class Outcome {
        public final String status,summary;
        public final boolean modelSuccess,cleanupKnown,blocked;
        Outcome(String status,String summary,boolean success,boolean cleanup,boolean blocked){
            this.status=status;this.summary=summary;this.modelSuccess=success;
            this.cleanupKnown=cleanup;this.blocked=blocked;
        }
    }
""" + parts["stop"] + """
    public Outcome finish(String previousStatus,String previousSummary,boolean previousSuccess,
                          boolean previousCleanup,boolean previouslyBlocked){
        String taskId="33333333333333333333333333333333";
        String finalStatus=previousStatus,summary=previousSummary;
        boolean modelSuccess=previousSuccess,cleanup=previousCleanup,controllerSuccess=false;
        blocked=previouslyBlocked;
""" + parts["close_result"] + """
        running=false;
        return new Outcome(finalStatus,summary,modelSuccess,cleanup,blocked);
    }
}
"""
    service_fixture="package org.trillionnium.hepta.local;\nfinal class HeptaAccessibilityService {\n"+parts["message_helpers"]+"\n}\n"
    files = []
    for name, value in (("LocalInference.java", local_inference),
                        ("ControllerFinalizationFixture.java", fixture),
                        ("HeptaAccessibilityService.java", service_fixture)):
        path = output / name
        path.write_text(value, encoding="utf-8")
        files.append(path)
    files.append(package / "TaskCancellationQueue.java")
    digest = lambda value: hashlib.sha256(value).hexdigest()
    record = {
        "scope": "Exact production Stop method, endTask/exception handling, post-close scope check, terminal decisions and TaskCleanup; Android UI, model and scope/config IO are fixtures",
        "completion_boundary": "Exact production cleanup/status block; controller-workflow candidate is false in this legacy fixture, while the derived terminal and completion identity execute in the full-controller harness",
        "scope_io_default": "absent; all original 13 cases retained; configured production checks also run in qualification-scope full-controller harness",
        "cancellation_boundary": "Actual TaskCancellationQueue with asynchronously started host worker; captured service/task and monotonic clock are explicit fixtures; test barriers wait for the real queue drain before releasing model teardown",
        "task_cancellation_queue_sha256": digest((package / "TaskCancellationQueue.java").read_bytes()),
        "controller_sha256": digest(controller.encode()),
        "inference_sha256": digest(inference.encode()),
        "service_sha256": digest(service.encode()),
        "extracted_parts": {name: {"bytes": len(value.encode()), "sha256": digest(value.encode())}
                            for name, value in parts.items()},
        "generated_files": {path.name: digest(path.read_bytes()) for path in files},
        "not_android_runtime": True,
        "not_model_inference": True,
        "not_phone_test": True,
    }
    (output / "EXTRACTION.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return files, record
