"""Actual native-session closure for the eight ordinary-routing entry cases.

Only generated Android installed-app and observation IO fixtures are adapted.
Production Session/Observation/Domain/providers, UI/session/controller entry bodies
and the original routing cases/assertions are compiled and executed unchanged.
"""
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


def prepare(source, output, entries):
    source, output = Path(source), Path(output)
    package = source / "src/org/trillionnium/hepta/local"
    legacy = source / "tests/native-app/legacy-boundary/NativeAppSession.java"
    config_path = package / "QualificationScopeConfig.java"
    paths = [Path(p).resolve() for p in entries]
    require(paths.count(legacy.resolve()) == 1 and paths.count(config_path.resolve()) == 1,
            "exact old native IO and installed IO compiler inputs required")
    config = config_path.read_bytes()
    old_class = part(config.decode(),
            "    /** Read-only reuse of the existing full installed-APK capture/unchanged check.\n",
            "    /** APK-set hash = ")
    template = source / "tests/native-app-routing/InstalledIdentityFixture.template"
    replacement = template.read_bytes()
    require(sha(replacement) == "2cd5ef0db6c38491754f70d6cf71770b913e70dc8762a5ffa7c15185f43d8060",
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
    service_after = service.replace(old_prepare, new_prepare, 1).replace(old_observation, new_observation, 1).encode()
    require(service.replace(old_prepare, "", 1).replace(old_observation, "", 1)
            == service_after.decode().replace(new_prepare, "", 1).replace(new_observation, "", 1),
            "production-extracted Service methods changed outside explicit observation IO")
    service_path.write_bytes(service_after)
    paths = [p for p in paths if p not in (legacy.resolve(), config_path.resolve())]
    actual = [package / (name + ".java") for name in
              ("NativeAppSession", "NativeActionSnapshotCheck", "NativeCtripFlightPage", "NativeXiaomiProductPage")]
    paths += [generated_config, *actual]
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
        ],
        "production_extracted_service_methods_unchanged": True,
        "actual_native_classes": [metadata(p, p.read_bytes()) for p in actual],
        "android_runtime": False, "phone_operations": 0, "model_inference": False,
        "provider_or_business_verified": False,
        "observation_boundary": "One complete synthetic unknown page, same real Selection/authorization/UUID and actual NodeRef signature helper; no query result, screen acquisition or Android installation proof.",
    }
    return paths, record
