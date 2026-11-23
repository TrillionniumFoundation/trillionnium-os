"""Compile-only absent automatic-mode types for the original manual route gate.

The separate automatic-target gate compiles the complete actual four production
files and real settings transaction. These legacy cases remain manual; every
new automatic provenance constructor/endpoint is private or always refusing.
"""
import hashlib
from pathlib import Path


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def need(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def ref(path):
    raw = path.read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}


RESOLVER = b'''package org.trillionnium.hepta.local;
/** Compiler shape only. No automatic-mode selection can be constructed. */
final class BackgroundAutoTargetResolver {
    private BackgroundAutoTargetResolver(){throw unavailable();}
    static final class StartSelection {
        final Entry entry=null;
        final NativeAppGoal nativeGoal=null;
        final String sha256=null;
        private StartSelection(){throw unavailable();}
        void requireOwner(String owner){throw unavailable();}
        java.util.Map<String,Object> evidence(){throw unavailable();}
    }
    static final class Entry {
        final Choice choice=null;
        private Entry(){throw unavailable();}
        String packageName(){throw unavailable();}
    }
    static final class Choice {
        final org.trillionnium.hepta.background.ProfileTarget profileTarget=null;
        private Choice(){throw unavailable();}
    }
    private static UnsupportedOperationException unavailable(){
        return new UnsupportedOperationException("Automatic target authority absent in original manual route cases");
    }
}
'''

UI_PORTS = '''
    // Original manual cases have no automatic mode or pending automatic Start.
    private final Object automaticReadyStart=null;
    private String automaticStartFeedback;
    private boolean automaticMode(){return false;}
    private boolean prepareAutomaticStart(String owner,String source,String nonce){throw automaticUnavailable();}
    private BackgroundSession.Selection automaticStartSelection(String owner){throw automaticUnavailable();}
    private void requireAutomaticSchedule(String owner){throw automaticUnavailable();}
    private void invalidateAutomaticStart(){throw automaticUnavailable();}
    private static UnsupportedOperationException automaticUnavailable(){
        return new UnsupportedOperationException("Automatic UI absent in original manual route cases");
    }
'''


def prepare_types(source, output, paths):
    source, output = Path(source), Path(output)
    paths = list(paths)
    existing = [Path(p) for p in paths if Path(p).name == "BackgroundAutoTargetResolver.java"]
    shared = Path(source) / "tests/native-app/legacy-boundary/BackgroundAutoTargetResolver.java"
    local = output / "BackgroundAutoTargetResolver.java"
    need(not existing or (existing in ([shared], [local]) and existing[0].read_bytes() == RESOLVER),
         "manual route must not mix actual, changed or duplicate automatic resolver")
    target = source / "src/org/trillionnium/hepta/local/BackgroundTaskTarget.java"
    need(target in paths, "actual full target must remain a compiler input")
    generated = existing[0] if existing else local
    output.mkdir(parents=True, exist_ok=True)
    if not existing:
        with generated.open("xb") as stream:
            stream.write(RESOLVER)
    return (paths if existing else paths + [generated]), {
        "schema": "hepta.manual-route-automatic-absent.v1",
        "actual_target_source": ref(target),
        "generated_resolver": ref(generated),
        "shared_exact_refusing_compiler_input": existing == [shared],
        "reused_exact_refusing_compiler_input": bool(existing),
        "all_new_constructors_private_and_throwing": True,
        "all_new_authority_endpoints_always_refuse": True,
        "automatic_mode_or_selection_executed": False,
    }


def prepare_ui(source, output, paths, java_block):
    paths, metadata = prepare_types(source, output, paths)
    ui = Path(output) / "ScopeUiFixture.java"
    before = ui.read_bytes()
    ports = UI_PORTS.encode()
    count = before.count(ports)
    need(count in (0, 1), "one exact absent-mode block in old manual UI fixture")
    base = before.replace(ports, b"", 1) if count else before
    need(b"boolean automaticMode()" not in base,
         "no actual or changed automatic-mode implementation in old manual UI fixture")
    source_method = java_block(
        (Path(source) / "src/org/trillionnium/hepta/local/MainActivity.java").read_bytes(),
        "private boolean beginTask(String owner,String source,String nonceSha)")
    need(before.decode().count(source_method) == 1,
         "complete actual beginTask required before compiler extension")
    end = base.rfind(b"}")
    need(end >= 0 and not base[end + 1:].strip(), "one final generated UI class")
    after = base[:end] + ports + base[end:]
    need((not count or before == after) and after.replace(ports, b"", 1) == base
         and after.decode().count(source_method) == 1,
         "every old generated byte and actual entry method must remain")
    if not count:
        ui.write_bytes(after)
    metadata.update({"ui_before": {"bytes": len(base), "sha256": sha(base)},
                     "ui_input": {"bytes": len(before), "sha256": sha(before)},
                     "reused_exact_ui_ports": bool(count),
                     "ui_after": ref(ui), "exact_inverse": True,
                     "actual_begin_task_sha256": sha(source_method.encode()),
                     "actual_begin_task_verbatim": True,
                     "automatic_mode_always_false": True})
    return paths, metadata
