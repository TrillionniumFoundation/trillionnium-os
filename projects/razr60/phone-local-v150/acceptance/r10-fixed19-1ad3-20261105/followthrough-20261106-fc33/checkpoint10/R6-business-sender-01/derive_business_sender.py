#!/usr/bin/env python3
"""Copy the exact reviewed dialog block into the actually called business sender.

No sender module import, actor construction, nonce, command execution or phone
operation occurs. The standalone source must later live directly under B so its
unchanged BASE-relative dependencies retain their exact original meaning.
"""
import ast
import difflib
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
REVIEW = HERE.parent
PARENT = REVIEW/'R5-e2e-plan/references/send_new_native_task_r5.py'
BLOCK = REVIEW/'R6-sender-ui/candidate02/CLOSE-DETAILS.new.txt'
OLD = REVIEW/'R6-sender-ui/CLOSE-DETAILS.old.txt'
COMPONENT = REVIEW/'R6-sender-ui/candidate02/send_new_native_guard_task_r10_r4.py'
PARENT_PIN = {'bytes':40788,'sha256':'5ab04019e94adb989e9909ae3a9aa10db0689de62821ec549db8beb3ec4d0281'}
OLD_PIN = {'bytes':251,'sha256':'c22be16b96afaa791e75cf8531854bf0064e8cb9b830e87bd85e4c2bbaabbcd5'}
NEW_PIN = {'bytes':818,'sha256':'5c88d8b8c4c88fe2605abb55239d21c233e97037ebfdcfb9346f4c4ee2e528f5'}
COMPONENT_PIN = {'bytes':41647,'sha256':'546010c5ef2c8f99d2be71a9f99d608c41186bdfc9a70e7d64b286fe133e3045'}


def pin(raw):
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def enc(value):
    return (json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode()


def main():
    parent=PARENT.read_bytes();old=OLD.read_bytes();new=BLOCK.read_bytes();component=COMPONENT.read_bytes()
    assert pin(parent)==PARENT_PIN and pin(old)==OLD_PIN and pin(new)==NEW_PIN and pin(component)==COMPONENT_PIN
    assert parent.count(old)==1 and parent.count(new)==0 and component.count(new)==1
    candidate=parent.replace(old,new)
    assert candidate.count(new)==1 and candidate.replace(new,old)==parent
    compile(candidate,'business-sender-source-candidate','exec')
    # Check the changed bytes are solely in the pre-existing generated-actor string.
    a,b=ast.parse(parent),ast.parse(candidate)
    def strings(tree):
        return [n.value for n in ast.walk(tree) if isinstance(n,ast.Constant) and isinstance(n.value,str)]
    old_strings,new_strings=strings(a),strings(b)
    assert len(old_strings)==len(new_strings)
    changed=[(x,y)for x,y in zip(old_strings,new_strings)if x!=y]
    assert len(changed)==1 and changed[0][0].count(old.decode())==1
    assert changed[0][1].replace(new.decode(),old.decode())==changed[0][0]
    actor_before,actor_after=changed[0]
    compile(actor_after,'reviewed-generated-actor-fragment','exec')
    assert actor_after.count("send_attempted=True")==actor_before.count("send_attempted=True")==1
    assert actor_after.count("tap(send)")==actor_before.count("tap(send)")==1
    assert new.rstrip().endswith(b"assert node(nodes,'org.trillionnium.owneropen:id/ui_prompt').attrib['text']==expected")
    assert b"assert node(nodes,'org.trillionnium.owneropen:id/ui_prompt').attrib.get('package')=='org.trillionnium.owneropen'" in new
    source_name='send_new_native_task_r5_fc33_r6.py'
    out=HERE/'candidate';out.mkdir(mode=0o700)
    def put(name,raw):
        with(out/name).open('xb')as stream:stream.write(raw)
    put(source_name,candidate);put('CLOSE-DETAILS.old.txt',old);put('CLOSE-DETAILS.new.txt',new)
    patch=''.join(difflib.unified_diff(parent.decode().splitlines(True),candidate.decode().splitlines(True),
        fromfile='actual-called/send_new_native_task_r5.py',tofile=source_name))
    put('SOURCE.patch',patch.encode())
    proof=dict(schema='hepta.fc33.business-sender.same-reviewed-dialog-block.v1',
        state='HOST_SOURCE_CANDIDATE_ONLY_NOT_PUBLISHED_OR_RUN',parent=dict(path=str(PARENT),**PARENT_PIN),
        component_candidate=dict(path=str(COMPONENT),**COMPONENT_PIN),old_block=OLD_PIN,new_block=NEW_PIN,
        candidate=dict(path=source_name,**pin(candidate)),full_byte_inverse=True,
        changed_generated_actor_string_count=1,original_outer_sender_AST_other_than_that_string_unchanged=True,
        original_single_Send_site_unchanged=True,original_exact_text_assertion_unchanged=True,
        last_iteration_owner_editor_check_present=True,
        basename_must_be_published_directly_under_original_B=True,
        operator_still_requires_two_path_literals_and_SENDER_SHA_propagation=True,
        root_host_XML_controls='Root owns the actual 23-original XML control; not duplicated or claimed here.',
        phone_calls=0,model_requests=0,actor_constructions=0,native_sends=0,new_nonces=0,
        actual_runtime_R6=None,actual_BUILD=None,actual_READY=None,actual_E2E=None,fixed19_credit=0)
    put('SOURCE-DELTA.json',enc(proof))
    print(json.dumps(dict(source=pin(candidate),proof=pin(enc(proof)),phone_calls=0,source_only=True),sort_keys=True))


if __name__=='__main__':
    main()
