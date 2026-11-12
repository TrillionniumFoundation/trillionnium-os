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
        "message_helpers": section(service, "    static String limited(", "\n}"),
    }
    local_inference = (
        "package org.trillionnium.hepta.local;\n"
        "public interface LocalInference {\n"
        + parts["cleanup_contract"]
        + "void cancelTask();\nTaskCleanup endTask();\n}\n"
    )
    fixture = """package org.trillionnium.hepta.local;
import java.util.concurrent.atomic.AtomicBoolean;
public final class ControllerFinalizationFixture {
    private final LocalInference inference;
    private final AtomicBoolean cancelled=new AtomicBoolean();
    private final Object handleLock=new Object();
    private volatile boolean running=true,blocked,terminalDecisionSealed;
    private Handle activeInference;
    /** Scope/config IO seam; default absent preserves all original 13 cases. */
    public interface ScopeCheck { void verifyUnchanged() throws Exception; }
    private ScopeCheck scope;
    /** Type-only Owner boundary; this legacy fixture cannot create an authorized Frame. */
    private static final class TaskAuthorization {
        private interface Frame { boolean successAllowed(); }
    }
    private interface AuthorizationCheck { void ready(); TaskAuthorization.Frame frame(); }
    private final AuthorizationCheck authorization=new AuthorizationCheck(){
        public void ready(){}
        public TaskAuthorization.Frame frame(){throw new AssertionError("legacy fixture has no controller-workflow candidate");}
    };
    /** Explicit non-Web contract; no helper close proof or Web completion is provided. */
    private static final class TaskCompletionGate {
        private static final String WEB="web_search_results";
        private static final class Contract { private final String kind="unverified_goal"; }
        private final Contract contract=new Contract();
    }
    private final TaskCompletionGate completion=new TaskCompletionGate();
    public void setScopeCheck(ScopeCheck check){scope=check;}
    private interface Handle { void cancel(); }
    private void emit(String value) { /* Android listener fixture; no IO. */ }
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
    digest = lambda value: hashlib.sha256(value).hexdigest()
    record = {
        "scope": "Exact production Stop method, endTask/exception handling, post-close scope check, terminal decisions and TaskCleanup; Android UI, model and scope/config IO are fixtures",
        "completion_boundary": "Exact production cleanup/status block; controller-workflow candidate is false in this legacy fixture, while the derived terminal and completion identity execute in the full-controller harness",
        "scope_io_default": "absent; all original 13 cases retained; configured production checks also run in qualification-scope full-controller harness",
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
