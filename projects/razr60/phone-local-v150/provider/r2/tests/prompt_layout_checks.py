#!/usr/bin/env python3
"""Host-only regression checks for the r2 prompt layout. Never contacts any service."""
import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
import secrets
import sys
import types

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/"source"))
import provider_phone_local as local

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def expect_reject(operation):
    try:
        operation()
    except local.ProviderError:
        return
    raise AssertionError("expected a closed rejection")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--health01-inputs",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    args=p.parse_args()
    actual_in=(args.health01_inputs/"provider-in.jsonl").read_bytes()
    actual_request=(args.health01_inputs/"local-01.request.json").read_bytes()
    start=json.loads(actual_in.splitlines()[0])
    owner=start["turn"]["user_input"]
    old=json.loads(actual_request)
    original_scope=json.loads(old["messages"][1]["content"][0]["text"])
    original_users=[m for m in original_scope["transcript"] if m.get("role")=="user"]
    assert len(original_users)==1 and original_users[0]["content"]==owner
    context={key:value for key,value in original_scope.items() if key!="transcript"}
    messages=[{"role":"system","content":"Original inherited baseline policy."},
              {"role":"user","content":owner}]
    phone=types.SimpleNamespace(calls={},verified_facts={})
    new=local.compose_local_messages(messages,copy.deepcopy(messages),phone,context,[],24576)
    checks=[]
    def check(name,ok):
        if not ok: raise AssertionError(name)
        checks.append(name)
    check("r1_actual_user_input_was_not_dropped",original_users[0]["content"]==owner)
    check("r2_owner_text_exact_utf8_last",new[-1]["role"]=="user"
          and new[-1]["content"][0]["text"].encode()==owner.encode())
    check("r2_three_messages_context_separate",len(new)==3 and isinstance(new[1]["content"],str))
    metadata=json.loads(new[1]["content"])
    check("owner_not_duplicated_as_context_transcript",not any(
        row.get("role")=="user" for row in metadata["transcript"]))
    check("owner_hash_bound",metadata["owner_request_utf8_sha256"]==sha(owner.encode()))
    check("policy_unchanged",new[0]["content"]==old["messages"][0]["content"]==local.POLICY)
    check("source_and_transcript_not_mutated",messages[1]["content"]==owner
          and "transcript" not in context and original_scope["transcript"]==original_users)
    check("r1_actual_limits_preserved",old["max_tokens"]==256 and old["temperature"]==0
          and old["stream"] is False)
    consumed=len(metadata and new[1]["content"].encode())+len(local.POLICY.encode())+len(owner.encode())
    expect_reject(lambda:local.compose_local_messages(messages,messages,phone,context,[],consumed-1))
    checks.append("total_prompt_budget_includes_owner_and_context")
    expect_reject(lambda:local.compose_local_messages(messages+[messages[1]],messages,phone,context,[],24576))
    checks.append("duplicate_owner_role_rejected")
    altered=copy.deepcopy(messages);altered[1]["content"]+=" "
    expect_reject(lambda:local.compose_local_messages(messages,altered,phone,context,[],24576))
    checks.append("projected_owner_byte_change_rejected")
    unicode_text="离线新文本-"+secrets.token_hex(12)+" 🦉\n\"双引号\" $HOME \\"
    alternate=[messages[0],{"role":"user","content":unicode_text}]
    image={"type":"image_url","image_url":{"url":"data:image/jpeg;base64,/9j/2Q=="}}
    projection=local.compose_local_messages(alternate,alternate,phone,context,[image],24576)
    check("unicode_newline_emoji_bytes_unchanged",
          projection[-1]["content"][0]["text"].encode()==unicode_text.encode())
    check("only_current_image_preserved_exactly",projection[-1]["content"][1:]==[image]
          and len(projection[-1]["content"])==2)
    expect_reject(lambda:local.compose_local_messages(alternate,alternate,phone,context,[image,image],24576))
    checks.append("multiple_images_rejected")
    for file in (ROOT/"source").glob("*.py"):
        ast.parse(file.read_bytes(),feature_version=(3,12))
    check("all_sources_python3_12_syntax",True)
    # The failed model answer is retained as r1 evidence; the fixture never calls _decision or dispatches it.
    response=(args.health01_inputs/"local-01.http-response.json").read_bytes()
    decision=json.loads(json.loads(response)["choices"][0]["message"]["content"])
    check("observed_bad_action_retained_not_replayed",
          decision["kind"]=="tool.call" and decision["tool"]=="phone.open_app"
          and decision["command"]=="org.trillionnium.hepta.controlprobe" and decision["argv"]==[])
    report={"schema":"hepta.prompt-layout-host-validation.v150.2","status":"PASS",
            "assertions":len(checks),"checks":checks,
            "source_sha256":sha((ROOT/"source/provider_phone_local.py").read_bytes()),
            "parent_actual_request_sha256":sha(actual_request),
            "parent_provider_in_sha256":sha(actual_in),
            "parent_response_sha256":sha(response),
            "owner_request_utf8_sha256":sha(owner.encode()),
            "r1_projection_bug":False,"r2_fixture_only_not_model_qualification":True,
            "projected_model_request_bytes":len(json.dumps(new,ensure_ascii=False,separators=(",",":")).encode()),
            "actual_phone_operations":0,"actual_model_requests":0,"old_action_replayed":False}
    args.out.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    with args.out.open("xb") as stream:
        stream.write((json.dumps(report,ensure_ascii=False,sort_keys=True,indent=2)+"\n").encode())
    args.out.chmod(0o600)
    print(json.dumps(report,ensure_ascii=False,separators=(",",":")))

if __name__=="__main__":
    main()
