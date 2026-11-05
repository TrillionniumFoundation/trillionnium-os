"""One explicit retirement resolution for a retained failed action.

The proof is produced by a separate offline verifier plus Root's bound review.
This module never connects to either executor and never changes a task terminal.
Only a new, pinned executor can accept future, independently claimed tasks.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from provider_openai_compatible import ProviderError
from phone_local_http_worker import strict_json

ACTION_ID = 'fc7bd6d939fb740a6403a04521fbb057'
INTENT_SHA256 = '37f047bc0f06ad65eb5c20673e45eba4b257df864d5482ae454f553eba7cb417'
COMMAND_SHA256 = '7976b489740b138a22fb8d724f953af92b7a1e3a1c15b5b60941482ab497487f'
VERIFIER_SHA256 = '6645922db85d02d71b1b8a9542af19ef6b343d5c599c91c0c4f9bb96757fe981'
# Frozen offline verifier + independent Root review; this is not a sidecar success receipt.
PROOF_SHA256 = '2bdd6c33c42359f1b27567b99627f7223d40a0c37f6af0158b8dc010e899943e'
PROOF_STATE = 'VERIFIED_EVIDENCE_FOR_EXPLICIT_NEW_VERSION_RESOLUTION'
RESOLUTION_STATE = 'confirmed_not_executed_after_executor_retirement'
EXECUTOR_BINDING = {'revision': 6, 'endpoint': 'hepta_phone_executor_v150_r6', 'client_path': '/var/lib/trillionnium/owner-open/phone-local-v150/tool_client_r6_output600000_1ad3_01.py', 'client_sha256': '21020cc22e6a20a2827acc0bcf777cfea67591bc6f1e0d5b29c45bf4d90b03c9'}
ORIGINAL_ARTIFACTS = {
    'before': 'ee698fc195b52360b87b9196163d0bd32b3455daa6769b91dfd67a93e8c26744',
    'after': '740e70772a71a3b12bcddb4488452d497960781a7aa2ea021e7e379183d1457e',
    'native_records': '3acdcdbde2ce5673816751664a706c11a07b3fc1976f7a598af398cdc4f4f806',
    'native_report': 'd94e0ca4b809073abe1bd8750837e1107ca7837eb9c44a85ce7325bd6f229818',
}
ORIGINAL_EXECUTOR = {
    'server_instance': 'ec17ea0567048b7094ac702fa4321d7d', 'pid': 31206,
    'start_ticks': 6437072, 'boot_id': 'f8019f83-20a7-4f18-bea1-51c980621e4d',
    'binary_sha256': '30a495061ec8370e15391fd579a254ce35818c7b019725538e0a34755a36ccaa',
    'source_sha256': 'beedc3a1a178d4b75887773e8ea1feae508cef89a692b35a03da3134893cafb4',
    'endpoint': 'hepta_phone_local_v150', 'actions_dev': 65086, 'actions_ino': 136105,
}


def require(ok, reason):
    if not ok:
        raise ProviderError('[retirement_recovery] ' + reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_private_proof(path):
    path = Path(path)
    require(path.is_absolute() and path.parent.resolve(strict=True) == path.parent,
            'canonical private proof path required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600
                and 0 < before.st_size <= 262144, 'proof ownership/type/bound differs')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(262145)
        after, named = os.fstat(fd), path.lstat()
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
        require(len(raw) == before.st_size and all(getattr(before, key) == getattr(after, key)
                == getattr(named, key) for key in fields), 'proof changed while read')
    finally:
        os.close(fd)
    return raw


def validate_proof(raw, intent, intent_sha256):
    require(re.fullmatch('[0-9a-f]{64}', PROOF_SHA256) is not None
            and sha(raw) == PROOF_SHA256, 'only the frozen real retirement proof is admitted')
    value = strict_json(raw)
    require(isinstance(value, dict) and value.get('schema') == 'hepta.executor-retirement-proof.v150.1'
            and value.get('state') == PROOF_STATE
            and value.get('action_id') == ACTION_ID
            and value.get('intent_sha256') == INTENT_SHA256 == intent_sha256
            and value.get('command_sha256') == COMMAND_SHA256
            and value.get('verifier_sha256') == VERIFIER_SHA256
            and value.get('artifact_sha256') == ORIGINAL_ARTIFACTS
            and value.get('retired_executor') == ORIGINAL_EXECUTOR,
            'original case/verifier/executor/proof bindings differ')
    require(all(value.get(key) is True for key in
                ('automatic_checks_pass', 'external_review_verified', 'eligible_for_new_version_resolution',
                 'original_task_terminal_unchanged'))
            and all(value.get(key) is False for key in
                    ('resolution_written', 'business_verified', 'automatic_replay', 'old_claims_edited')),
            'proof cannot qualify or tries to rewrite the old task')
    require(re.fullmatch('[0-9a-f]{64}', value.get('external_review_original_sha256', ''))
            and isinstance(value.get('external_evidence'), list) and value['external_evidence'],
            'independent Root review binding absent')
    details = value.get('details', {})
    require(details.get('native_hash_verification', {}).get('status') == 'PASS'
            and details.get('native_terminal', {}).get('exit_code') == 71,
            'original failed native execution proof is absent')
    require(intent.get('schema') == 'hepta.action-intent.v150.1'
            and intent.get('action_id') == ACTION_ID and intent.get('command_sha256') == COMMAND_SHA256
            and intent.get('state') == 'reserved_before_native_dispatch_result_unknown'
            and all(details.get('original_request_scope', {}).get(key) == val
                    for key, val in intent['semantic_identity'].items()),
            'retirement proof cannot resolve a different original intent')
    return value


def retain_original_proof(path, raw):
    """One durable append. A crash may reuse only these exact already pinned bytes."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        require(read_private_proof(path) == raw, 'retained retirement proof differs; never overwrite it')
        return sha(raw)
    with os.fdopen(fd, 'wb') as out:
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    return sha(raw)


def validate_retired_resolution(directory, intent, intent_sha256, resolution):
    expected = {'schema', 'action_id', 'intent_sha256', 'state', 'retirement_proof_sha256',
                'verifier_sha256', 'retired_executor', 'future_executor_binding', 'observed_utc',
                'business_verified', 'automatic_replay', 'original_task_terminal_unchanged',
                'old_effect_replay_forbidden'}
    require(set(resolution) == expected and resolution.get('schema') == 'hepta.action-resolution.v150.2'
            and resolution.get('action_id') == ACTION_ID and resolution.get('intent_sha256') == INTENT_SHA256
            and resolution.get('state') == RESOLUTION_STATE
            and resolution.get('retirement_proof_sha256') == PROOF_SHA256
            and resolution.get('verifier_sha256') == VERIFIER_SHA256
            and resolution.get('retired_executor') == ORIGINAL_EXECUTOR
            and resolution.get('future_executor_binding') == EXECUTOR_BINDING
            and resolution.get('business_verified') is False and resolution.get('automatic_replay') is False
            and resolution.get('original_task_terminal_unchanged') is True
            and resolution.get('old_effect_replay_forbidden') is True,
            'retirement resolution is not the exact additive frozen type')
    observed = datetime.datetime.fromisoformat(resolution['observed_utc'])
    require(observed.tzinfo is not None, 'retirement observation timestamp is not timezone-bound')
    raw = read_private_proof(Path(directory)/(ACTION_ID+'.retirement-proof.json'))
    return validate_proof(raw, intent, intent_sha256)


def require_r6_terminal(receipt):
    """Process outcome only; this never establishes an application postcondition."""
    require(receipt.get('terminal') is True
            and receipt.get('state') in {'completed', 'failed', 'timed_out', 'cancelled', 'output_limit_exceeded'}
            and receipt.get('executor_revision') == 6
            and receipt.get('executor_context') == 'u:r:trillionnium_owner_open_phone_executor:s0'
            and receipt.get('peer_context') == 'u:r:trillionnium_owner_open_bootstrap:s0'
            and receipt.get('execution_context') == 'u:r:trillionnium_owner_open_phone_worker:s0'
            and receipt.get('execution_credentials_scope') == 'android_shell_uid2000'
            and receipt.get('handshake_stage') == 'worker_entry_after_exec_transition'
            and all(receipt.get(key) is True for key in
                ('effect_started', 'process_group_established', 'waitpid_joined', 'process_group_absent',
                 'execution_credentials_verified', 'supplementary_groups_cleared', 'worker_domain_verified'))
            and all(type(receipt.get(key)) is int and receipt[key] == 2000 for key in
                ('required_execution_uid', 'required_execution_gid', 'execution_uid', 'execution_euid',
                 'execution_gid', 'execution_egid'))
            and type(receipt.get('execution_supplementary_group_count')) is int
            and receipt['execution_supplementary_group_count'] == 0
            and type(receipt.get('dispatch_count')) is int and receipt['dispatch_count'] == 1
            and type(receipt.get('pid')) is int and receipt['pid'] > 1
            and type(receipt.get('pgid')) is int and receipt['pgid'] == receipt['pid']
            and receipt.get('waitpid_identity_lost') is False,
            'original r6 receipt does not prove its exact worker/process terminal')
