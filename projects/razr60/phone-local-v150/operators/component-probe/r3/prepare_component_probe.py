#!/usr/bin/env python3
"""Prepare one NEW component contract and owner request on an operator host.

This creates local files only. It never opens a network socket, runs a phone
command, resolves a prior action or transmits a task.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import time

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--session-id", required=True)
    p.add_argument("--profile-id", required=True)
    p.add_argument("--executor-instance", required=True)
    p.add_argument("--retirement-proof", type=Path, required=True)
    p.add_argument("--retirement-resolution", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    source = Path(__file__).resolve().with_name("component_probe_provider.py")
    spec = importlib.util.spec_from_file_location("probe_definition", source)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    def digest(path):
        raw = path.read_bytes()
        m.require(0 < len(raw) <= 262144, "operator_proof_file_bound")
        m.decode(raw)  # Syntax only: final proof semantics belong to the independent verifier.
        return m.sha(raw)
    nonce = secrets.token_hex(16)
    c = {"schema": "hepta.native-component-probe.contract.v150.r6.1",
         "nonce": nonce, "owner_request_sha256": m.sha(m.owner_request(nonce).encode()),
         "selected_session_id": a.session_id, "selected_profile_id": a.profile_id,
         "executor_server_instance": a.executor_instance, "executor_journal": m.JOURNAL,
         "endpoint": m.SOCKET, "client_sha256": m.CLIENT_SHA, "parent_sha256": m.PARENT_SHA,
         "worker_sha256": m.WORKER_SHA, "policy_rule_sha256": m.POLICY_RULE_SHA,
         "patched_policy_sha256": m.PATCHED_POLICY_SHA,
         "retirement_proof_sha256": digest(a.retirement_proof),
         "retirement_resolution_sha256": digest(a.retirement_resolution),
         "provider_source_sha256": m.sha(source.read_bytes()),
         "expires_unix_ms": int(time.time()*1000)+15*60*1000, "scope": m.SCOPE}
    m.validate_contract(c)
    os.umask(0o077)
    a.out.mkdir(mode=0o700, parents=False, exist_ok=False)
    m.create(a.out/"contract.json", c)
    request = m.owner_request(nonce).encode()
    fd = os.open(a.out/"request.txt", os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(request); stream.flush(); os.fsync(stream.fileno())
    m.sync_dir(a.out)
    result = {"state": "PREPARED_NOT_SENT", "nonce": nonce,
              "owner_request_sha256": m.sha(request),
              "contract_sha256": m.sha((a.out/"contract.json").read_bytes()),
              "phone_contract_path": str(m.STATE/"contracts"/(nonce+".json")),
              "phone_provider_source_path": str(m.STATE/"source-r3/component_probe_provider.py"),
              "phone_provider_evidence_root": str(m.STATE/"evidence"),
              "phone_executor_journal": m.JOURNAL,
              "proof_gate": "operator must independently verify pinned retirement proof and actual resolution",
              "phone_operations": 0, "model_requests": 0, "task_submissions": 0}
    m.create(a.out/"PREPARED.json", result)
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
