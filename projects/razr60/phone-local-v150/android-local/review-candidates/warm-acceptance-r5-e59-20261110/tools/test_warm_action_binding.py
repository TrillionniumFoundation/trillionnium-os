"""Synthetic completed warm tasks; actual collector and action verifier, no phone.

Some mutations deliberately reseal the host inventory while leaving its prior
success flags true. A pass must therefore depend on rechecked source contracts,
not a schema allowlist or a cached/edited collection verdict.
"""
import copy
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import phone_acceptance as acceptance
import phone_suite as suite
from test_warm_receipts import fixture, G, UID

TASK, FIRST, SECOND = "a" * 32, "d" * 32, "0" * 32
PACKAGE = "com.android.settings"
INSTRUCTION = "打开设置，然后报告完成。"


def write(path, value):
    acceptance.write_json(path, value)


def basic_source(root, corrected=False):
    """Controller-shaped journals; reverse run-name order is intentional."""
    owner_sha = acceptance.digest(INSTRUCTION.encode())
    write(root / "task/owner.json", dict(task_id=TASK, instruction=INSTRUCTION,
                                       instruction_utf8_sha256=owner_sha))
    for step, run_id, kind in ((1, FIRST, "open"), (2, SECOND, "done")):
        before_id, after_id = "%032x" % (step * 2), "%032x" % (step * 2 + 1)
        before = dict(observation_id=before_id, package="com.motorola.launcher" if step == 1 else PACKAGE,
                      nodes=[])
        action = dict(action=kind, observation_id=before_id, package=PACKAGE)
        if kind == "done": action["status"] = "success"
        prefix = root / "task" / ("step-%02d" % step)
        raw = (json.dumps(action, ensure_ascii=False) + "\n").encode()
        write(Path(str(prefix) + "-before.json"), before)
        write(Path(str(prefix) + "-after.json"), dict(observation_id=after_id, package=PACKAGE, nodes=[]))
        write(Path(str(prefix) + "-action.json"), dict(action=action, model_issued=True, model_run_id=run_id,
              accepted=True, dispatched=kind == "open", stale=False))
        write(Path(str(prefix) + "-model-0.json"), dict(run_id=run_id, raw_text=raw.decode(),
              observation_id=before_id, original_instruction_sha256=owner_sha))
        run = root / "runs" / run_id
        run.mkdir(parents=True)
        (run / "raw-text.txt").write_bytes(raw)
        prompt = "UNTRUSTED_DATA\n" + json.dumps(dict(screen=before, apps=[[PACKAGE, "设置"]]), ensure_ascii=False)
        (run / "prompt.txt").write_text(prompt + "\nOWNER\n" + INSTRUCTION)
    write(root / "task/result.json", dict(task_id=TASK, steps=2, status="model_reported_done",
          model_reported_success=True, cleanup_known=True, final_observation_id="%032x" % 5))
    if corrected:
        selected = root / "task/step-01-model-0.json"
        selected.rename(selected.with_name("step-01-model-1.json"))
        rejected = "9" * 32
        first = json.loads(selected.with_name("step-01-model-1.json").read_bytes())
        first.update(run_id=rejected, raw_text='{"invalid_controller_decision":true}')
        write(selected, first)
        target = root / "runs" / rejected
        target.mkdir()
        (target / "raw-text.txt").write_text(first["raw_text"])
        (target / "prompt.txt").write_bytes((root / "runs" / FIRST / "prompt.txt").read_bytes())


class SourceFiles:
    """Only the collector's read methods; intentionally no command method."""
    def __init__(self, source, task_id):
        self.source, self.task_id = source, task_id

    def local(self, path):
        task = "files/control-tasks/" + self.task_id
        if path == task or path.startswith(task + "/"):
            return self.source / "task" / path[len(task):].lstrip("/")
        if path == "files/runs" or path.startswith("files/runs/"):
            return self.source / "runs" / path[len("files/runs"):].lstrip("/")
        raise AssertionError("unexpected collector path: " + path)

    def list_children(self, path, directories=False):
        directory = self.local(path)
        if not directory.is_dir(): return []
        if directories:
            return sorted(p.name for p in directory.iterdir() if p.is_dir())
        return sorted(p.name for p in directory.iterdir() if p.is_file())

    def app_bytes(self, path, optional=False):
        file = self.local(path)
        if optional and not file.exists(): return None
        return file.read_bytes()


def collect_warm(source, directory, verdict="pass", compute="npu"):
    """Add the full native/app protocol to synthetic controller journals."""
    # Complete synthetic observations at construction time. The real verifier
    # never fills absent evidence. The frozen core fixture's homepage already
    # supplies these fields; older non-home test builders omitted their values.
    for path in (source / "task").glob("step-*.json"):
        if not path.name.endswith(("-before.json", "-after.json")):
            continue
        observation = json.loads(path.read_bytes())
        observation.setdefault("window_id", 1)
        observation.setdefault("rotation", 0)
        state = json.dumps({"package": observation.get("package"), "nodes": observation.get("nodes", [])}, sort_keys=True)
        observation.setdefault("observation_state_sha256", acceptance.digest(state.encode()))
        write(path, observation)
    owner = json.loads((source / "task/owner.json").read_bytes())
    task_id, instruction = owner["task_id"], owner["instruction"]
    app_session, native_session, _, _, templates, _, _ = fixture()
    models = sorted((source / "task").glob("step-*-model-*.json"))
    model_path = "/synthetic-model/" + acceptance.MODEL_FILE
    for sequence, model_file in enumerate(models, 1):
        model = json.loads(model_file.read_bytes())
        run_id, run = model["run_id"], source / "runs" / model["run_id"]
        raw, prompt = (run / "raw-text.txt").read_bytes(), (run / "prompt.txt").read_bytes()
        before = json.loads(model_file.with_name(model_file.name.split("-model-")[0] + "-before.json").read_bytes())
        grammar, system = b'root ::= "synthetic grammar fixture"\n', b"Synthetic local controller system."
        (run / "grammar.gbnf").write_bytes(grammar); (run / "system.txt").write_bytes(system)
        app, native = copy.deepcopy(templates[0])
        native.update(task_id=task_id, request_id=run_id, request_sequence=sequence,
            model_hash_performed_this_request=sequence == 1, model_reset_count=sequence,
            runtime="llama_cpp", mode="llm", compute_requested=compute,
            device_resolved="HTP0" if compute == "npu" else "GPUOpenCL", device_warning=None,
            n_ctx_create=4096, n_gpu_layers_create=-1, model_path=model_path, max_tokens=256,
            raw_text_utf8=True, raw_text_truncated=False, raw_text_bytes=len(raw), raw_text_sha256=acceptance.digest(raw), error=None,
            input_sha256=dict(prompt=acceptance.digest(prompt), system=acceptance.digest(system), grammar=acceptance.digest(grammar)),
            prompt_budget=dict(method="lfm3_rendered_utf8_bytes_upper_bound", model_contract_sha256=acceptance.MODEL_SHA256,
                checked=True, admitted=True, is_exact_token_count=False, formatted_utf8_bytes=500,
                bos_eos_upper=2, generation_tokens=256, reserved_tokens=256, total_context_upper=1014, context_tokens=4096))
        app.update(task_id=task_id, run_id=run_id, request_sequence=sequence, worker_started_this_request=sequence == 1,
            package_name=acceptance.PACKAGE, runtime="llama_cpp", mode="llm", compute_requested=compute,
            context_tokens=4096, model_sha256_verified=acceptance.MODEL_SHA256, model_path=model_path,
            image_sent_to_model=False, fallback_allowed=False, native_context_budget_valid=True,
            grammar_constraint_enabled=True, grammar_binding_valid=True, native_result_binding_valid=True,
            grammar_schema="hepta.observed-action-gbnf.v1", grammar_sha256=acceptance.digest(grammar),
            grammar_observation_id=before["observation_id"], grammar_current_package=before["package"],
            prompt_sha256=acceptance.digest(prompt), raw_text_sha256_read=acceptance.digest(raw),
            native_receipt=copy.deepcopy(native))
        write(run / "app-receipt.json", app); write(run / "native-result.json", native)
    count = len(models)
    native_session.update(task_id=task_id, requests_received=count, requests_completed=count, model_reset_count=count)
    app_session.update(task_id=task_id, requests_sent=count, requests_accepted=count,
                       native_session_receipt=copy.deepcopy(native_session))
    generation = source / "runs" / G
    write(generation / "app-session-receipt.json", app_session)
    write(generation / "native-session-result.json", native_session)
    (generation / "stderr.log").write_text("llama_model_load: offloaded 25/25 layers to GPU\n"
        "llama_model_load: " + ("HTP0" if compute == "npu" else "OpenCL") + " model buffer size = 1000.00 MiB\n")
    (generation / "stdout.log").write_bytes(b"")
    final = json.loads((source / "task/result.json").read_bytes())
    final.update(external_model=False, model_session=dict(worker_generation=G, task_id=task_id,
        process_started=True, process_exit_observed=True, exit_code=0, receipt_valid=True,
        app_receipt_sha256=acceptance.digest((generation / "app-session-receipt.json").read_bytes())))
    write(source / "task/result.json", final)
    collection = acceptance.collect_evidence(SourceFiles(source, task_id), directory, task_id, instruction,
        set(), False, UID, compute, 4096, expected_final=final)
    if not acceptance.collection_verified(collection):
        raise AssertionError("synthetic collector fixture invalid: " + json.dumps(collection))
    report = dict(schema="hepta.host-acceptance.v1", case_id=directory.name, task_id=task_id,
                  instruction=instruction, instruction_sha256=owner["instruction_utf8_sha256"], app_uid=UID,
                  task_result=final, native_receipts_verified=True, collection=collection,
                  cleanup_unknown=False, verdict=verdict, launch_attempt_count=1)
    write(directory / "acceptance.json", report)
    return report


def reseal(directory, synchronize_terminal=False):
    """An adversarial edited host summary must not bypass source validation."""
    collection = json.loads((directory / "collection.json").read_bytes())
    if synchronize_terminal:
        final = json.loads((directory / "task/result.json").read_bytes())
        final["model_session"]["app_receipt_sha256"] = acceptance.digest(
            (directory / "runs" / G / "app-session-receipt.json").read_bytes())
        write(directory / "task/result.json", final)
    inventories = [collection["files"]] + [row["files"] for row in collection["associated_runs"] + collection["task_model_sessions"]]
    for files in inventories:
        for item in files:
            path = directory / item["path"]
            if path.is_file():
                data = path.read_bytes(); item.update(bytes=len(data), sha256=acceptance.digest(data))
    write(directory / "collection.json", collection)
    report = json.loads((directory / "acceptance.json").read_bytes())
    report["collection"] = copy.deepcopy(collection)
    if synchronize_terminal: report["task_result"] = json.loads((directory / "task/result.json").read_bytes())
    write(directory / "acceptance.json", report)


class WarmActionBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for target in ((acceptance, "Adb"), (socket, "create_connection"), (subprocess, "Popen"), (subprocess, "run")):
            guard = patch.object(*target, side_effect=AssertionError("phone/network/process access forbidden"))
            guard.start(); self.addCleanup(guard.stop)

    def case(self, name="case", corrected=False, compute="npu"):
        source, directory = self.root / (name + "-source"), self.root / name
        basic_source(source, corrected)
        collect_warm(source, directory, compute=compute)
        return directory

    def action_result(self, directory):
        return suite.action_sequence(directory, [{"action": "open", "package": PACKAGE}],
                                     acceptance.digest(INSTRUCTION.encode()))

    def reject(self, directory):
        result = self.action_result(directory)
        self.assertFalse(result["passed"], result)
        self.assertFalse(result["evidence_complete"], result)
        self.assertTrue(result["missing_evidence"], result)

    def change(self, directory, relative, mutate):
        path = directory / relative
        value = json.loads(path.read_bytes()); mutate(value); write(path, value)

    def test_complete_warm_action_sequence_with_reverse_run_name_order(self):
        directory = self.case()
        result = self.action_result(directory)
        self.assertTrue(result["passed"], result); self.assertTrue(result["evidence_complete"], result)
        binding = result["model_action_bindings"][0]
        self.assertEqual((binding["task_id"], binding["worker_generation"], binding["request_sequence"]), (TASK, G, 1))
        self.assertEqual(binding["generation_requests_verified"], 2)
        self.assertIs(binding["generation_process_exit_observed"], True)
        self.assertEqual(binding["generation_exit_code"], 0)
        done_path = directory / "task/step-02-action.json"
        done = suite.model_action_binding(directory, done_path, json.loads(done_path.read_bytes()),
            json.loads((directory / "task/step-02-before.json").read_bytes()))
        self.assertTrue(done["verified"], done); self.assertEqual(done["request_sequence"], 2)

    def test_corrected_second_attempt_preserves_complete_sequence(self):
        result = self.action_result(self.case(corrected=True))
        self.assertTrue(result["passed"], result)
        binding = result["model_action_bindings"][0]
        self.assertEqual(binding["request_sequence"], 2)
        self.assertEqual(binding["generation_requests_verified"], 3)
        self.assertTrue(binding["step_model_receipt"].endswith("-model-1.json"))

    def test_gpu_generation_can_qualify_with_its_exact_log(self):
        result = self.action_result(self.case(compute="gpu"))
        self.assertTrue(result["passed"], result)

    def test_all_terminal_and_collection_artifacts_are_required(self):
        paths = ("acceptance.json", "collection.json", "task/result.json",
                 "runs/" + G + "/app-session-receipt.json", "runs/" + G + "/native-session-result.json",
                 "runs/" + G + "/stderr.log", "runs/" + SECOND + "/app-receipt.json")
        for i, path in enumerate(paths):
            with self.subTest(missing=path):
                directory = self.case("missing%d" % i); (directory / path).unlink(); self.reject(directory)

    def test_request_or_session_semantic_damage_cannot_reuse_success_flags(self):
        cases = [("runs/" + SECOND + "/native-result.json", "worker_generation", "f" * 32),
                 ("runs/" + SECOND + "/app-receipt.json", "request_committed", False),
                 ("runs/" + SECOND + "/native-result.json", "raw_text_sha256", "f" * 64),
                 ("runs/" + G + "/app-session-receipt.json", "process_exit_observed", False),
                 ("runs/" + G + "/app-session-receipt.json", "exit_code", None),
                 ("runs/" + G + "/app-session-receipt.json", "cancel_requested", True),
                 ("runs/" + G + "/app-session-receipt.json", "force_destroy_sent", True),
                 ("runs/" + G + "/native-session-result.json", "requests_completed", 1),
                 ("runs/" + G + "/native-session-result.json", "sdk_destroy_rc", -1)]
        for i, (relative, field, value) in enumerate(cases):
            with self.subTest(path=relative, field=field):
                directory = self.case("semantic%d" % i)
                self.change(directory, relative, lambda item: item.update({field: value}))
                reseal(directory, synchronize_terminal=True)
                self.assertTrue(acceptance.collection_verified(json.loads((directory / "collection.json").read_bytes())))
                self.reject(directory)

    def test_generation_sequence_cannot_be_spliced_or_reordered(self):
        for mode in ("gap", "duplicate", "reordered"):
            with self.subTest(mode=mode):
                directory = self.case(mode)
                sequences = {FIRST: 2 if mode == "reordered" else 1,
                             SECOND: 3 if mode == "gap" else 1}
                for run_id, sequence in sequences.items():
                    relative = "runs/" + run_id + "/"
                    self.change(directory, relative + "native-result.json", lambda value: value.update(
                        request_sequence=sequence, model_reset_count=sequence, model_hash_performed_this_request=sequence == 1))
                    native = json.loads((directory / relative / "native-result.json").read_bytes())
                    self.change(directory, relative + "app-receipt.json", lambda value: value.update(
                        request_sequence=sequence, worker_started_this_request=sequence == 1, native_receipt=native))
                collection = json.loads((directory / "collection.json").read_bytes())
                for row in collection["associated_runs"]: row["request_sequence"] = sequences[row["run_id"]]
                write(directory / "collection.json", collection); reseal(directory); self.reject(directory)

    def test_model_journals_cannot_skip_a_controller_step(self):
        source, directory = self.root / "source", self.root / "case"
        basic_source(source)
        for path in (source / "task").glob("step-02-*.json"):
            path.rename(path.with_name(path.name.replace("step-02-", "step-03-")))
        final_path = source / "task/result.json"
        final = json.loads(final_path.read_bytes()); final["steps"] = 3; write(final_path, final)
        collect_warm(source, directory)
        self.reject(directory)

    def test_unlisted_owned_request_and_missing_step_journal_are_incomplete(self):
        directory = self.case("hidden")
        write(directory / "runs" / ("e" * 32) / "app-receipt.json", dict(schema="unknown", task_id=TASK, worker_generation=G))
        self.reject(directory)
        directory = self.case("no-step")
        (directory / "task/step-02-model-0.json").unlink()
        collection = json.loads((directory / "collection.json").read_bytes())
        collection["files"] = [v for v in collection["files"] if v["path"] != "task/step-02-model-0.json"]
        write(directory / "collection.json", collection); reseal(directory); self.reject(directory)

    def test_prompt_must_bind_selected_step_not_another_valid_observation(self):
        directory = self.case()
        prefix = directory / "runs" / FIRST
        prompt = (prefix / "prompt.txt").read_bytes().replace(b'"observation_id": "' + b"0" * 31 + b'2"',
                                                              b'"observation_id": "' + b"0" * 31 + b'4"')
        (prefix / "prompt.txt").write_bytes(prompt)
        self.change(directory, "runs/" + FIRST + "/native-result.json", lambda value: value["input_sha256"].update(prompt=acceptance.digest(prompt)))
        native = json.loads((prefix / "native-result.json").read_bytes())
        self.change(directory, "runs/" + FIRST + "/app-receipt.json", lambda value: value.update(
            prompt_sha256=acceptance.digest(prompt), native_receipt=native))
        reseal(directory); self.reject(directory)

    def test_changed_raw_action_step_owner_and_observation_are_rejected(self):
        changes = [("task/step-01-model-0.json", lambda v: v.update(raw_text="changed")),
                   ("task/step-01-action.json", lambda v: v["action"].update(package="other.application")),
                   ("task/step-01-before.json", lambda v: v.update(observation_id="f" * 32)),
                   ("task/owner.json", lambda v: v.update(task_id="f" * 32)),
                   ("task/result.json", lambda v: v.update(cleanup_known=False))]
        for i, (relative, change) in enumerate(changes):
            with self.subTest(path=relative):
                directory = self.case("binding%d" % i); self.change(directory, relative, change)
                reseal(directory); self.reject(directory)

    def test_warm_schema_downgrade_cannot_use_oneshot_fast_path(self):
        directory = self.case()
        self.change(directory, "runs/" + FIRST + "/native-result.json", lambda v: v.update(schema="hepta.geniex-once.result.v1"))
        reseal(directory); self.reject(directory)

    def test_missing_offload_and_runtime_evidence_fail_after_resealing(self):
        for mode in ("log", "device", "budget", "grammar", "system"):
            with self.subTest(mode=mode):
                directory = self.case(mode)
                if mode == "log": (directory / "runs" / G / "stderr.log").write_text("CPU model buffer only\n")
                elif mode == "system": (directory / "runs" / SECOND / "system.txt").write_text("changed")
                elif mode == "grammar": (directory / "runs" / SECOND / "grammar.gbnf").write_text("changed")
                else:
                    self.change(directory, "runs/" + SECOND + "/native-result.json", lambda v: v.update(
                        {"device_resolved": "CPU"} if mode == "device" else {"prompt_budget": {}}))
                    native = json.loads((directory / "runs" / SECOND / "native-result.json").read_bytes())
                    self.change(directory, "runs/" + SECOND + "/app-receipt.json", lambda v: v.update(native_receipt=native))
                reseal(directory); self.reject(directory)

    def test_embedded_boolean_numeric_mutation_is_rejected(self):
        for i, (relative, embedded) in enumerate((("runs/" + SECOND + "/app-receipt.json", "native_receipt"),
                                                ("runs/" + G + "/app-session-receipt.json", "native_session_receipt"))):
            directory = self.case("bool%d" % i)
            self.change(directory, relative, lambda value: value[embedded].update(process_exit_observed=0))
            reseal(directory, synchronize_terminal=True); self.reject(directory)

    def test_collection_corruption_cannot_raise_or_keep_cached_approval(self):
        for i, mutate in enumerate((lambda v: v.update(task_model_sessions=[None]),
                                   lambda v: v.update(associated_runs=[None]),
                                   lambda v: v.update(errors=["incomplete collection"]))):
            directory = self.case("corrupt%d" % i)
            self.assertTrue(self.action_result(directory)["passed"])
            self.change(directory, "collection.json", mutate)
            collection = json.loads((directory / "collection.json").read_bytes())
            self.change(directory, "acceptance.json", lambda v: v.update(collection=collection))
            self.reject(directory)

    def test_symlink_and_stale_inventory_fail_closed(self):
        for mode in ("link", "bytes"):
            directory = self.case(mode)
            path = directory / "runs" / SECOND / "prompt.txt"
            if mode == "link":
                saved = self.root / "outside-prompt.txt"; saved.write_bytes(path.read_bytes())
                path.unlink(); path.symlink_to(saved)
            else: path.write_bytes(path.read_bytes() + b" ")
            self.reject(directory)


if __name__ == "__main__":
    unittest.main()
