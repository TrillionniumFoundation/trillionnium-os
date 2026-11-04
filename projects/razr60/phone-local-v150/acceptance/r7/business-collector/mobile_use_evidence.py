"""Pure byte-pinned validation of r7 named JSON to legacy semantic decisions.

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

PROVIDER_SHA256="8f57e86ec66e4588e2e6f43ea761f17e9ae02361791995ff2f5831a16e46dbe6"
PROVIDER_BYTES=55325
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
    rows=[r for r in seal["production_files"] if r["path"]=="source/provider_phone_local.py"]
    require(len(rows)==1 and rows[0]["sha256"]==PROVIDER_SHA256
            and rows[0]["bytes"]==PROVIDER_BYTES,"unreviewed named-action provider source pin")
    path=Path(provider_source).absolute()/"provider_phone_local.py"
    raw=snapshot.read(path)
    require(len(raw)==PROVIDER_BYTES and sha(raw)==PROVIDER_SHA256,
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
    api={"copy":copy,"hashlib":hashlib,"json":json,"re":re,
         "ProviderError":ValueError,"require":require}
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
    elif tool=="phone.input_text":
        require(semantic.get("package")==args[0] and semantic.get("view_id")==args[1]
                and semantic.get("expected_text")==args[2]
                and semantic.get("requested_text")==decision["command"],
                "projected Unicode fields differ from original semantic action")
    elif tool=="phone.read_text":
        require(semantic.get("package")==args[0] and semantic.get("view_ids")==args[1:],
                "projected public readback fields differ")
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
    mobile=api["mobile_use_schema"](legacy)
    expected_format={"type":"json_schema","json_schema":{
        "name":"hepta_mobile_use_action","strict":True,"schema":mobile}}
    require(exact(body.get("response_format"),expected_format),
            "request decoder differs from original recorded legacy grammar projection")
    require(len(body["messages"])==3 and body["messages"][0].get("role")=="system"
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
    observation=projected.get("observation_status")
    require(isinstance(observation,dict) and set(observation)=={
        "current_image_present","attempted_action_count","verified_fact_count",
        "catalogue_and_request_are_not_screen_observations"},
        "explicit observation status fields differ")
    require(type(observation["current_image_present"]) is bool
            and observation["current_image_present"]==bool(images["images"])
            and type(observation["attempted_action_count"]) is int
            and observation["attempted_action_count"]==len(previous)
            and type(observation["verified_fact_count"]) is int
            and 0<=observation["verified_fact_count"]<=len(previous)
            and observation["catalogue_and_request_are_not_screen_observations"] is True,
            "model prompt overstates image or prior action evidence")
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
        "projection_provider_source_sha256":PROVIDER_SHA256,
        "original_action":model_action["arguments"]["action"],
        "projection_is_execution_or_business_success":False,**binding}
