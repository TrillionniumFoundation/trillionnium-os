"""Pure byte-pinned validation of selected r10 named JSON projections.

No model, socket, command mapper or sidecar operation is invoked. Only five
pure functions and two literal constants are extracted from the exact selected
provider bytes. Original HTTP and evidence files remain unmodified.
"""
import ast
import copy
import hashlib
import json
from pathlib import Path
import re
from native_journal_audit import strict_loads

PROJECTION_FRAGMENTS_SHA256="b86a027b0fcb6aea55b845c42c7b3af916eebeee20148eb8d49485f08d86127b"
FOCUS_INPUT_JAR="/data/local/tmp/hepta-phone-executor-v150-r9-r1/helpers/focus-text-input-v150-r9.jar"
FOCUS_INPUT_JAR_SHA256="c8ec62529d88a29872c313052cdd335dc7611b11089db87531008b35d926e855"
# All 15 reviewed sources are pinned before importing original pure parsers.
# This includes task authorization, transcript context and the daily PARENTS seal.
# A caller cannot authorize altered parser code merely by supplying a new seal.
REVIEWED_HELPER_SOURCE_PINS={
    "action_ledger.py": "50620b2e27334b7cf311bd6b1c743d71c19c32887e5ed31a07fdf54dac0e7907",
    "daily_phone_local.py": "ca23c60bbb4114960c6a571492cacd9e0bdc3404191409ac78bcf0c34a06c1d0",
    "health_contracts.py": "00adea791c00eaac52f65716cb158ee73f38bdded96f1718578ec92f5091d32d",
    "ledger_round_evidence.py": "87d2b8731883dd06806a45851867332c568fe02deb2b9b8952094b86822e678d",
    "model_health.py": "105b401fbab1c151e890a3e6e4774322eb62a9e7799744b4d3cef01b6e1c0f80",
    "model_slot_cleanup.py": "9144bc864e245d63186f6b37760562e3b42554fdcc42ed792c9081761f315183",
    "phone_local_http_worker.py": "a1f1c94f2e78ced93cbde2113f508d756507249133f71c6dbe9a82a58a232d4d",
    "phone_local_tools.py": "0302a8bac9dac18234c9493aa512e1efcf43d7cc5eaab884882dad42c2182c54",
    "phone_observation_tools.py": "2c5ebb75e34fcce4c14638939809dade1f6d129504270930c8f94e2c2ce15b66",
    "phone_task_guards.py": "87d88e0e9f93b31cf69bf0e4cdb9c62fd20e03c2192a0ffec621eb84c26bba86",
    "provider_codex_host.py": "cbdeaaf819ef2fa2d67d3d9707dae86eac6303d6caa4bf194b37cd0816177039",
    "provider_openai_compatible.py": "337c83284fece94c0dd477a30029c63017b7eb00aab55a747b89b193823820bc",
    "provider_phone_local.py": "082b02a473dc4d75d46a895895b64b96cf25ae24fc61795cb292fc70fd8d9ad6",
    "retirement_recovery.py": "c1f5a77e32264f5f638f62f005f57c66fffeb60cf288ad036848ac4fceb74827",
    "task_postconditions.py": "d4984cce3e25609d0bc3ef97475edfe74d4795244722e654eb654df3b6e6ceb3"
}
SOURCE_NAMES={"action_ledger.py","daily_phone_local.py","health_contracts.py",
    "ledger_round_evidence.py","model_health.py","model_slot_cleanup.py",
    "phone_local_http_worker.py","phone_local_tools.py","phone_observation_tools.py",
    "phone_task_guards.py","provider_codex_host.py","provider_openai_compatible.py",
    "provider_phone_local.py","retirement_recovery.py","task_postconditions.py"}
FUNCTIONS=("_mobile_schema_matches","mobile_use_schema","mobile_use_policy",
           "normalize_mobile_use","mobile_mapping_evidence")
CONSTANTS=("MOBILE_USE_POLICY","MOBILE_USE_HINTS")
def require(ok,reason):
    if not ok: raise ValueError(reason)
def sha(raw): return hashlib.sha256(raw).hexdigest()
def canonical(value):
    return json.dumps(value,ensure_ascii=False,sort_keys=True,
                      separators=(",",":"),allow_nan=False).encode()
def exact(left,right): return canonical(left)==canonical(right)

def load_projection_api(snapshot,provider_source,seal):
    require(provider_source is not None and isinstance(seal,dict),
            "named-action collection requires selected source and seal")
    rows=seal.get("production_files")
    require(isinstance(rows,list) and len(rows)==len(SOURCE_NAMES),"complete r10 source inventory required")
    pins={}
    for row in rows:
        require(isinstance(row,dict) and isinstance(row.get("path"),str),"source pin shape differs")
        relative=Path(row["path"])
        require(len(relative.parts)==2 and relative.parts[0]=="source"
                and relative.name in SOURCE_NAMES and relative.name not in pins
                and type(row.get("bytes")) is int and 0<row["bytes"]<=1024*1024
                and isinstance(row.get("sha256"),str) and re.fullmatch("[0-9a-f]{64}",row["sha256"]),
                "source pin identity differs")
        raw=snapshot.read(Path(provider_source).absolute()/relative.name)
        require(len(raw)==row["bytes"] and sha(raw)==row["sha256"],"selected production/helper source bytes differ")
        pins[relative.name]=row
    require(set(pins)==SOURCE_NAMES,"selected source/helper inventory incomplete")
    require(all(pins[name]["sha256"]==digest for name,digest in REVIEWED_HELPER_SOURCE_PINS.items()),
            "selected typed helper/ledger source bytes are not reviewed")
    provider_pin=pins["provider_phone_local.py"]
    path=Path(provider_source).absolute()/"provider_phone_local.py"
    raw=snapshot.read(path)
    require(len(raw)==provider_pin["bytes"] and sha(raw)==provider_pin["sha256"],
            "named-action provider original bytes differ")
    tree=ast.parse(raw,filename=str(path))
    selected=[]
    for node in tree.body:
        if isinstance(node,ast.FunctionDef) and node.name in FUNCTIONS:
            selected.append(node)
        elif isinstance(node,ast.Assign) and len(node.targets)==1:
            target=node.targets[0]
            if isinstance(target,ast.Name) and target.id in CONSTANTS:
                ast.literal_eval(node.value)
                selected.append(node)
    require({n.name for n in selected if isinstance(n,ast.FunctionDef)}==set(FUNCTIONS)
            and len(selected)==len(FUNCTIONS)+len(CONSTANTS),"pure projection extraction differs")
    fragments={n.name if isinstance(n,ast.FunctionDef) else n.targets[0].id:
               sha(ast.get_source_segment(raw.decode("utf-8"),n).encode()) for n in selected}
    require(sha(canonical(fragments))==PROJECTION_FRAGMENTS_SHA256,
            "selected projection function/constant bytes are not reviewed")
    api={"copy":copy,"hashlib":hashlib,"json":json,"re":re,
         "ProviderError":ValueError,"require":require,
         "projection_provider_source_sha256":provider_pin["sha256"],
         "verified_source_pins":pins}
    exec(compile(ast.Module(body=selected,type_ignores=[]),str(path)+"#pure-projection","exec"),api)
    return api

def semantic_binding(snapshot,run,decision,calls,number,image_hashes):
    matching=[call for call in calls if call["call_id"]==decision["call_id"]]
    if decision["kind"]!="tool.call":
        require(not matching,"terminal model action dispatched a native tool")
        return {"native_dispatch_for_this_action":False}
    require(len(matching)<=1,"mapped model call dispatched more than once")
    if not matching:
        # A mapper/admission refusal is retained as a refusal, never fabricated
        # into a native dispatch or successful execution.
        return {"native_dispatch_for_this_action":False}
    call=matching[0]
    semantic=snapshot.json(run/("semantic-"+sha(decision["call_id"].encode())+".json"))
    require(semantic.get("wire_call")==call and semantic.get("semantic_tool")==decision["tool"],
            "projected decision differs from original native semantic binding")
    tool,args=decision["tool"],decision["argv"]
    if tool=="phone.open_app":
        require(semantic.get("alias")==args[0],"projected open alias differs")
    elif tool=="phone.observe":
        require(semantic.get("package")==args[0],"projected observation package differs")
    elif tool in {"phone.input_text","phone.focus_input_text"}:
        require(semantic.get("package")==args[0] and semantic.get("view_id")==args[1]
                and semantic.get("expected_text")==args[2]
                and semantic.get("requested_text")==decision["command"],
                "projected Unicode fields differ from original semantic action")
        if tool=="phone.focus_input_text":
            require(semantic.get("input_contract")=="hepta.focused-unicode-input.v2"
                    and semantic.get("helper_path")==FOCUS_INPUT_JAR
                    and semantic.get("helper_sha256")==FOCUS_INPUT_JAR_SHA256
                    and semantic.get("focus_then_replace_one_user_intent") is True,
                    "projected focus input lost its exact reviewed v2 helper and intent")
    elif tool=="phone.read_text":
        require(semantic.get("package")==args[0] and semantic.get("view_ids")==args[1:],
                "projected public readback fields differ")
    elif tool=="phone.read_text_anchor":
        require(semantic.get("package")==args[0]
                and semantic.get("title_view_id")==args[1]
                and semantic.get("anchor_text")==args[2]
                and semantic.get("value_view_id")==args[3]
                and semantic.get("selector_schema")=="hepta.public-text-anchor.v150.1"
                and decision["command"]=="",
                "projected public anchor selector differs from the original semantic action")
    elif tool=="phone.tap":
        coordinate=snapshot.json(run/("local-%02d.coordinate-map.json"%number))
        xy=list(map(int,args[1:]))
        size=coordinate.get("encoded_size")
        require(isinstance(size,list) and len(size)==2
                and all(type(n) is int and n>0 for n in size),"coordinate map size differs")
        encoded=[min(size[0]-1,xy[0]*size[0]//1000),min(size[1]-1,xy[1]*size[1]//1000)]
        expected={"model_coordinate_units":"normalized_0_1000","model_xy":xy,
                  "encoded_size":size,"encoded_xy":encoded,"original_decision_unchanged":True}
        require(exact(coordinate,expected)
                and semantic.get("source_image_call_id")==args[0]
                and semantic.get("encoded_xy")==encoded
                and semantic.get("source_image_sha256") in image_hashes,
                "projected click lost current-image or original coordinate mapping")
    elif tool=="phone.screenshot":
        require(args==["0"] and decision["command"]=="","projected screenshot differs")
    elif tool=="phone.return_hepta":
        require(args==[] and decision["command"]==""
                and semantic.get("postcondition")=="actual_inner_display_focused_resumed_HEPTA",
                "projected HEPTA return differs")
    else:
        raise ValueError("unreviewed semantic tool")
    return {"native_dispatch_for_this_action":True,"original_semantic_binding_verified":True}

def verify_projection(snapshot,run,prefix,body,images,projected,raw_content,decision,
                      number,calls,image_hashes,api):
    require(isinstance(raw_content,str),"raw named-action content must be text")
    model_action=strict_loads(raw_content)
    action_path=run/(prefix+".model-action.json")
    mapping_path=run/(prefix+".mapping.json")
    saved_action=snapshot.json(action_path)
    mapping=snapshot.json(mapping_path)
    require(exact(model_action,saved_action),"saved original model object differs from raw HTTP content")
    request_id=images.get("request_id")
    require(isinstance(request_id,str) and re.fullmatch("[0-9a-f]{32}",request_id)
            and type(number) is int and 1<=number<=8,"model round/request ID differs")
    allowed="r%02d_%s"%(number,request_id[:16])
    require(projected.get("allowed_call_id")==allowed and type(projected.get("round")) is int
            and projected["round"]==number and type(projected.get("tools_remaining")) is int
            and projected["tools_remaining"]==max(0,8-number),"original round admission binding differs")
    legacy=mapping.get("legacy_schema")
    original_context=api["round_contexts"][number]
    require(exact(legacy,original_context["legacy_schema"])
            and exact(body["messages"],original_context["messages"]),
            "mapping grammar/history differs from complete original per-round reconstruction")
    mobile=api["mobile_use_schema"](legacy)
    expected_format={"type":"json_schema","json_schema":{
        "name":"hepta_mobile_use_action","strict":True,"schema":mobile}}
    require(exact(body.get("response_format"),expected_format),
            "request decoder differs from original recorded legacy grammar projection")
    require(body["messages"][0].get("role")=="system"
            and body["messages"][0].get("content")==api["mobile_use_policy"](mobile),
            "model named-action system prompt differs from selected source")
    for branch in legacy["oneOf"]:
        props=branch["properties"];kind=props["kind"]["const"]
        require(kind in ("tool.call","turn.complete")
                and props["call_id"]=={"const":allowed if kind=="tool.call" else ""},
                "legacy grammar call identity differs")
    normalized=api["normalize_mobile_use"](model_action,legacy,allowed)
    require(exact(normalized,decision),"saved legacy decision differs from deterministic model projection")
    expected=api["mobile_mapping_evidence"](model_action,normalized,legacy,allowed,
                                             raw_content,request_id,number)
    require(exact(mapping,expected),"original projection receipt/hash/identity differs")
    previous=[]
    for call in calls:
        match=re.fullmatch(r"r([0-9]{2})_[0-9a-f]{16}",call["call_id"])
        require(match is not None,"native call does not use existing round identity")
        if int(match[1])<number: previous.append(call)
    require(original_context["complete_earlier_ledger_prefix_verified"] is True
            and original_context["original_receipt_history_reparsed"] is True
            and original_context["schema_clock_endpoints_agree"] is True,
            "per-round original ledger/history proof is incomplete")
    prior_ids={call["call_id"] for call in previous}
    for row in projected["transcript"]:
        if row.get("role")=="tool_observation":
            require(row.get("content",{}).get("call_id") in prior_ids,
                    "model observation lacks an original prior native call")
    binding=semantic_binding(snapshot,run,normalized,calls,number,image_hashes)
    return {"named_action_projection_verified":True,
        "model_interface":"mobile_use_named_arguments_json_projection",
        "original_model_action_file_sha256":sha(snapshot.read(action_path)),
        "original_mapping_file_sha256":sha(snapshot.read(mapping_path)),
        "raw_model_content_sha256":sha(raw_content.encode()),
        "mapped_decision_canonical_sha256":sha(canonical(normalized)),
        "projection_provider_source_sha256":api["projection_provider_source_sha256"],
        "original_action":model_action["arguments"]["action"],
        "complete_earlier_ledger_prefix_verified":True,
        "original_receipt_history_reparsed":True,
        "request_binding_sha256":original_context["request_binding_sha256"],
        "excluded_open_aliases":original_context["excluded_open_aliases"],
        "projection_is_execution_or_business_success":False,**binding}
