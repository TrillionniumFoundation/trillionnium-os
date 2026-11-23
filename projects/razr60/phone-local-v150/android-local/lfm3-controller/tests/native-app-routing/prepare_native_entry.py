"""Actual native-session closure for the eight ordinary-routing entry cases.

Only generated Android installed-app and observation IO fixtures are adapted.
Production Session/Observation/Domain/providers, UI/session/controller entry bodies
and the original routing cases/assertions are compiled and executed unchanged.
"""
import ast
import hashlib
from pathlib import Path


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(ok, why):
    if not ok:
        raise RuntimeError(why)


def part(text, start, end):
    require(text.count(start) == 1 and text.count(end) == 1, "one exact entry IO section required")
    begin = text.index(start)
    return text[begin:text.index(end, begin)]


def metadata(path, raw):
    return {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}


def calendar_actual_session_ports(source, output, service):
    # Reuse only the exact already-reviewed literal ports, never execute that
    # helper or replace this gate's real controller with its type-only carrier.
    provider = source / "tests/native-app-provider/run_host.py"
    raw = provider.read_text()
    node = next(n for n in ast.parse(raw).body
                if isinstance(n, ast.FunctionDef) and n.name == "calendar_legacy_closure")
    require(sha(ast.get_source_segment(raw, node).encode()) ==
            "0b70b8ed6a4b7004114a321776d0adb1d0344937feba1d77614ce4ab17d6994e",
            "exact reviewed calendar compiler port helper required")
    values = {}
    for item in node.body:
        if isinstance(item, ast.Assign) and len(item.targets) == 1 and isinstance(item.targets[0], ast.Name):
            name = item.targets[0].id
            if name in ("actual_names", "calendar_types", "input_port", "model_port", "runtime_port"):
                values[name] = ast.literal_eval(item.value)
    require(set(values) == {"actual_names", "calendar_types", "input_port", "model_port", "runtime_port"},
            "complete reviewed literal port set required")
    # The new fixed helper must reverse exactly to the original reviewed helper.
    prior_helper = ast.get_source_segment(raw, node)
    inverse_pairs = [('"CalendarSelectionObservation", "NativeSearchFinalCensusResampleProof"', '"CalendarSelectionObservation"'), ('    static final class NativeSearchFinalCensusResampleProof {\n        private NativeSearchFinalCensusResampleProof(){throw new AssertionError("actual final-census producer unavailable in this pure gate");}\n        void consume(NativeSearchSession.Attempt attempt,NativeSearchRole role,long now){throw new AssertionError("no final-census replacement authority");}\n    }\n', ''), ('    runtime_port = """package org.trillionnium.hepta.local;\nfinal class RuntimeInferenceAdapter implements LocalInference {\n    private RuntimeInferenceAdapter(){throw new AssertionError("runtime router is outside this legacy fixture");}\n    public LocalRuntimeConfig configuration(){throw new AssertionError("no runtime configuration authority");}\n    public Handle generate(String prompt,String system,java.io.File image,DecisionGrammar grammar,int tokens,long timeout,Callback callback){throw new AssertionError("no runtime model execution");}\n    final class CalendarModelBinding {\n        private CalendarModelBinding(){throw new AssertionError("no runtime calendar binding in legacy fixture");}\n        VlmInferenceAdapter requireCurrent(String taskId,LocalRuntimeConfig config){throw new AssertionError("no runtime calendar producer authority");}\n    }\n    synchronized CalendarModelBinding bindCalendarModel(String taskId,LocalRuntimeConfig config){throw new AssertionError("no runtime calendar binding authority");}\n}\n"""\n', ''), ('(("VlmInferenceAdapter.java", model_port), ("LocalTaskController.java", controller_port), ("RuntimeInferenceAdapter.java", runtime_port))', '(("VlmInferenceAdapter.java", model_port), ("LocalTaskController.java", controller_port))')]
    for added, prior in inverse_pairs:
        require(prior_helper.count(added) == 1, "exact runtime/proof helper increment required")
        prior_helper = prior_helper.replace(added, prior, 1)
    require(sha(prior_helper.encode()) ==
            "0be32d214d355656fdbde067b892ec4dc8c7c13d95659b53cd66461066b661fb",
            "original calendar compiler helper changed beyond reviewed ports")
    qualification = source / "tests/qualification-scope/prepare_fixture.py"
    q = next(n for n in ast.parse(qualification.read_text()).body
             if isinstance(n, ast.FunctionDef) and n.name == "prepare")
    qports = next(ast.literal_eval(n.value) for n in q.body
                  if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "calendar_io_ports" for t in n.targets))
    require(sha(qports.encode()) == "d7362e7b663929fd7a835214534652c8bb0ad4747de2582bb14d3d3e23f3ed9d",
            "exact prior qualification calendar ports required")
    pairs = [
        ("    static final class CalendarFreshObservation {", "    interface CalendarActionCallback {"),
        ("    static final class CalendarActionResult {", "    static final class CalendarSelectionObservation {"),
        ("    static final class CalendarSelectionObservation {", "    void requireNativeCalendarSourceOwnership("),
    ]
    removed = []
    before = service
    for start, end in pairs:
        expected = part(qports, start, end)
        require(service.count(expected) == 1, "exact smaller refusing calendar shape required")
        service = service.replace(expected, "", 1)
        removed.append({"start": start, "bytes": len(expected.encode()), "sha256": sha(expected.encode())})
    types = values["calendar_types"]
    # This gate retains the original refusing search Session, which never
    # references the new final-census producer. Do not import its unused port.
    search_boundary = output / "NativeSearchSession.java"
    original_search = search_boundary.read_bytes()
    require(sha(original_search) ==
            "4ee12102d54c43142700a515938506ee6e46314ec4cecc1da0df121a1119801c",
            "exact original routing search boundary required")
    existing = b"        void requireUnclaimedRevalidated(long now){throw unavailable();}\n"
    retirement = b"        void requireUnclaimedForRetirement(long now){throw unavailable();}\n"
    require(original_search.count(existing) == 1 and retirement not in original_search,
            "one refusing Attempt boundary required")
    search_boundary.write_bytes(original_search.replace(existing, existing + retirement))
    unused_proof = part(types, "    static final class NativeSearchFinalCensusResampleProof {",
                        "    public static final class CalendarFreshObservation {")
    require(sha(unused_proof.encode()) ==
            "0983e5e5d8059e0655bc0324f3784f10670d3700a4c00207a83acfdf30da7b83",
            "exact unused final-census compiler port required")
    types = types.replace(unused_proof, "", 1)
    marker = "    public static final class CalendarActionResult {\n"
    # Keep the original controller ABI field; null is not a successful outcome.
    require(types.count(marker) == 1 and qports.count("        final ActionOutcome outcome=null;") == 1,
            "one original null calendar outcome field required")
    types = types.replace(marker, marker + "        final ActionOutcome outcome=null;\n", 1)
    require("class CalendarInputAttempt" not in service, "no duplicate calendar input attempt port")
    extension = types + values["input_port"]
    end = service.rfind("}")
    require(end >= 0 and not service[end + 1:].strip(), "one final Service boundary required")
    service = service[:end] + extension + service[end:]
    adapter = output / "VlmInferenceAdapter.java"
    adapter_before = adapter.read_bytes()
    require(b"private VlmInferenceAdapter()" in adapter_before and b"AcceptedRequestCallback" in adapter_before
            and b"class AcceptedRequest {" not in adapter_before, "original unconstructable Adapter boundary required")
    adapter.write_text(values["model_port"])
    runtime_adapter = output / "RuntimeInferenceAdapter.java"
    require(not runtime_adapter.exists(), "fresh refusing runtime boundary required")
    with runtime_adapter.open("x", encoding="utf-8") as handle:
        handle.write(values["runtime_port"])
    actual = [source / "src/org/trillionnium/hepta/local" / (n + ".java") for n in values["actual_names"]]
    return service, actual + [runtime_adapter], {
        "schema": "hepta.native-routing-calendar-compiler-boundary.v1",
        "reviewed_port_helper": metadata(provider, provider.read_bytes()),
        "reviewed_helper_body_sha256": sha(ast.get_source_segment(raw, node).encode()),
        "replaced_smaller_refusing_classes": removed,
        "service_before_sha256": sha(before.encode()), "service_after_sha256": sha(service.encode()),
        "service_extension_sha256": sha(extension.encode()),
        "adapter_before": metadata(adapter, adapter_before), "adapter_after": metadata(adapter, adapter.read_bytes()),
        "actual_pure_sources": [metadata(p, p.read_bytes()) for p in actual],
        "refusing_runtime_port": metadata(runtime_adapter, runtime_adapter.read_bytes()),
        "original_helper_exact_inverse": True,
        "unused_final_census_port_excluded_sha256": sha(unused_proof.encode()),
        "original_routing_search_boundary": metadata(search_boundary, original_search),
        "current_routing_search_boundary": metadata(search_boundary, search_boundary.read_bytes()),
        "real_controller_preserved": True, "all_new_authority_endpoints_always_refuse": True,
        "calendar_model_or_effect_executed": False,
    }


def prepare(source, output, entries):
    source, output = Path(source), Path(output)
    package = source / "src/org/trillionnium/hepta/local"
    legacy = source / "tests/native-app/legacy-boundary/NativeAppSession.java"
    config_path = package / "QualificationScopeConfig.java"
    paths = [Path(p).resolve() for p in entries]
    legacy_input = legacy.resolve()
    local_legacy = (output / "NativeAppSession.java").resolve()
    local_session_proof = None
    if paths.count(local_legacy) == 1 and legacy_input not in paths:
        raw_legacy = legacy.read_bytes()
        local = local_legacy.read_text()
        addition = part(local,
                "    /** Calendar ABI only. Constructors and every authority endpoint always refuse. */",
                "    private static UnsupportedOperationException unavailable(){")
        require(sha(raw_legacy) == "3fff6e7e892adca8a9e895a852447f55237124e6545c1fb3aa2c9b047a0e3ddd"
                and sha(addition.encode()) == "6143b28d3086ca7a1250a44e05a0b320dbf709eabc8d542ebf1fd47c0c4e2a1c"
                and local.replace(addition, "", 1).encode() == raw_legacy,
                "exact local calendar extension of original legacy Session required")
        legacy_input = local_legacy
        local_session_proof = {"original": metadata(legacy, raw_legacy),
                               "compiled_boundary": metadata(local_legacy, local_legacy.read_bytes()),
                               "added_ports_sha256": sha(addition.encode()), "exact_inverse": True}
    require(paths.count(legacy_input) == 1 and paths.count(config_path.resolve()) == 1,
            "exact old native IO and installed IO compiler inputs required")
    config = config_path.read_bytes()
    old_class = part(config.decode(),
            "    /** Read-only reuse of the existing full installed-APK capture/unchanged check.\n",
            "    /** APK-set hash = ")
    template = source / "tests/native-app-routing/InstalledIdentityFixture.template"
    replacement = template.read_bytes()
    require(sha(replacement) == "c5f1d82d5d1726b4a5ca8368d662e54adeb2100fadb64e42fb28264a6e6e6dd1",
            "reviewed native installed IO fixture differs")
    projected = config.decode().replace(old_class, replacement.decode(), 1).encode()
    generated_config = output / "QualificationScopeConfig.java"
    require(not generated_config.exists(), "fresh installed IO projection required")
    generated_config.write_bytes(projected)

    service_path = output / "HeptaAccessibilityService.java"
    service_before = service_path.read_bytes()
    service = service_before.decode()
    old_prepare = part(service, "    public void prepare(String pkg){\n", "    private PhoneObservation observation(){\n")
    new_prepare = old_prepare.replace(
            'root=new AccessibilityNodeInfo(pkg,7);node=new AccessibilityNodeInfo(pkg,7);node.text="测试";node.editable=true;node.scrollable=true;',
            'root=new AccessibilityNodeInfo(pkg,7);node=new AccessibilityNodeInfo(pkg,7);node.text="测试";node.editable=true;node.scrollable=true;\n'
            '        // Synthetic complete unknown page for this native routing entry only.\n'
            '        root.className="FrameLayout";root.bounds=new Rect(0,0,1080,2400);root.clickable=false;root.children.add(node);', 1)
    require(new_prepare != old_prepare, "one original synthetic prepare block required")
    old_observation = part(service, "    private PhoneObservation observation(){\n",
                           "    String observationTimeoutMessage(String taskId)")
    new_observation = '''    private PhoneObservation observation(){
        // Explicit host-only complete acquisition. No actual App screen or result is claimed.
        String id=String.format(java.util.Locale.ROOT,"%032x",++observations);
        String pkg=root==null?"":root.pkg;int window=root==null?-1:root.windowId;
        ObservedWindowMetadata metadata=ObservedWindowMetadata.observed(new int[]{0,0,1080,2400},"FrameLayout",1,root==null?0:root.window.display,new int[]{0,0,1080,2400},"Synthetic routing unknown page");
        List<PhoneObservation.Node> rows=new ArrayList<PhoneObservation.Node>();
        if(node!=null){
            Rect actualBounds=new Rect();node.getBoundsInScreen(actualBounds);
            ObservedChildText.Result child=observedChildText(node);
            NodeRef reference=new NodeRef(node,child,readScrollActions(node));
            rows.add(new PhoneObservation.Node("n0",node.pkg,node.className,node.viewId,node.text,node.description,actualBounds,node.clickable,node.editable,node.scrollable,node.enabled,node.focused,node.password,child,readScrollActions(node),readImeEnter(node),inputTextHash(node),node.editable&&node.focused&&node.enabled&&!node.password&&readImeEnter(node).queryAllowed()&&submitAvailable(node.pkg,inputTextHash(node)),reference.appTreeSignature,"0/0","FrameLayout",Boolean.valueOf(node.isSelected()),Boolean.valueOf(node.isCheckable()),Boolean.valueOf(node.isChecked())));
        }
        if(observationRows!=null)throw new AssertionError("native routing entry supplies its complete unknown-page IO only");
        int textUnits=0;for(PhoneObservation.Node n:rows)textUnits+=n.text.length()+n.description.length();
        PhoneObservation.CollectionStats collection=new PhoneObservation.CollectionStats(1536,512,6144,rows.size()+1,rows.size(),textUnits,0,0,0,0,0);
        return new PhoneObservation(id,pkg,SystemClock.elapsedRealtime(),1080,2400,0,window,new Rect(0,0,1080,2400),new File(getFilesDir(),"synthetic.png"),"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",new ObservationState("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",ImeVisibility.HIDDEN),metadata,false,rows,taskBackground==null?null:taskBackground.generation,taskBackground==null?null:taskBackground.selection.initialPackage,taskBackground==null?Collections.<String>emptyList():taskBackground.selection.allowedPackages,collection,taskBackground==null?null:backgroundSelectionJson(),taskBackground==null?null:taskBackground.ownerSha256);
    }
'''
    old_initial = part(service, "    void observeInitialNative(Object controller,Object nativeTask,String task,Object authorization,BackgroundSession background,\n",
                       "    /** Type-only legacy boundary; never a successful native-region recheck. */\n")
    new_initial = '''    void observeInitialNative(Object controller,Object nativeTask,String task,Object authorization,BackgroundSession background,
            File directory,Cancellation cancel,long deadline,long taskDeadline,ObservationCallback callback,InitialObservationRetryProof proof){
        // This ordinary-routing IO fixture supplies only its original deterministic first frame.
        // It cannot mint, consume or simulate a failed-read replacement.
        if(proof!=null)throw new AssertionError("native routing fixture cannot consume initial-read proof");
        if(controller==null||nativeTask==null||task==null||!task.equals(lease)
                ||authorization!=taskAuthorization||background!=taskBackground||taskObservationAdmissions!=0)
            throw new AssertionError("native routing fixture requires the first bound native read");
        taskObservationAdmissions++;
        observe(task,directory,cancel,deadline,callback);
    }
'''
    service_after = (service.replace(old_prepare, new_prepare, 1).replace(old_observation, new_observation, 1)
                     .replace(old_initial, new_initial, 1).encode())
    require(service.replace(old_prepare, "", 1).replace(old_observation, "", 1).replace(old_initial, "", 1)
            == service_after.decode().replace(new_prepare, "", 1).replace(new_observation, "", 1).replace(new_initial, "", 1),
            "production-extracted Service methods changed outside explicit observation IO")
    calendar_sources, calendar_record = [], None
    if local_session_proof is not None:
        service_text, calendar_sources, calendar_record = calendar_actual_session_ports(source, output, service_after.decode())
        service_after = service_text.encode()
    service_path.write_bytes(service_after)
    paths = [p for p in paths if p not in (legacy_input, config_path.resolve())]
    actual = [package / (name + ".java") for name in
              ('ObservationCaptureEvidence', "NativeAppSession", "NativeActionSnapshotCheck", "NativeCtripFlightPage", "NativeXiaomiProductPage")]
    paths += [generated_config, *actual, *calendar_sources]
    paths = list(dict.fromkeys(p.resolve() for p in paths))
    require(sum(p.name == "NativeAppSession.java" for p in paths) == 1
            and (package / "NativeAppSession.java").resolve() in paths, "only actual native Session may compile")
    record = {
        "schema": "hepta.native-routing-entry-io.v1",
        "scope": "Only eight new native routing entry cases; original qualification-scope uses unchanged legacy boundaries.",
        "production_installed_source": metadata(config_path, config),
        "production_installed_block_replaced_sha256": sha(old_class.encode()),
        "installed_io_template": metadata(template, replacement),
        "installed_compiler_projection": metadata(generated_config, projected),
        "installed_boundary": "Declared Ctrip expected APK hash is synthetic and separate from the exact host-file SHA; actual Installed.capture/verify are retained and each verifier rehashes the host file.",
        "observation_io_before": metadata(service_path, service_before),
        "observation_io_after": metadata(service_path, service_after),
        "observation_blocks": [
            {"name": "prepare", "before_sha256": sha(old_prepare.encode()), "after_sha256": sha(new_prepare.encode())},
            {"name": "observation", "before_sha256": sha(old_observation.encode()), "after_sha256": sha(new_observation.encode())},
            {"name": "initial_native_first_read", "before_sha256": sha(old_initial.encode()), "after_sha256": sha(new_initial.encode())},
        ],
        "production_extracted_service_methods_unchanged": True,
        "actual_native_classes": [metadata(p, p.read_bytes()) for p in actual],
        "local_legacy_session_exact_inverse": local_session_proof,
        "calendar_compiler_boundary": calendar_record,
        "android_runtime": False, "phone_operations": 0, "model_inference": False,
        "provider_or_business_verified": False,
        "observation_boundary": "One complete synthetic unknown page, same real Selection/authorization/UUID and actual NodeRef signature helper; no query result, screen acquisition or Android installation proof.",
    }
    return paths, record
