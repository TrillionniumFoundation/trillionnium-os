#!/usr/bin/env python3
"""Read one current native task's dedicated relay identity; never sends signals.

The raw task claim, provider's open original streams, its sole accepted socket,
the reverse TCP tuple, the owning relay, and the native parent's three pipes
must all agree. The result expires immediately: an operator must repeat these
checks while holding an exact pidfd before any separately reviewed injection.
"""
import argparse
import active_runtime_r10 as active
import base64
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

BASE = Path('/var/lib/trillionnium/owner-open/phone-local-v150')
PROC = Path('/proc')
PORT = 18080
RELAY = Path('/usr/libexec/trillionnium/provider-adapter')
RELAY_SHA = '5e48a5bfb06b9aeecbc7e510f07100df89321765545590cd7a6e97f780aff164'
RELAY_CONFIG = Path('/etc/trillionnium/owner-open/provider-host-relay-v1.json')
RELAY_CONFIG_SHA = '8a65beaed4b1737950ae02076607e429e8314bd9b9cb23d59d1f6be5979a75ea'
HOST = '/usr/libexec/trillionnium/trillionnium-owner-open-r5-host'
HOST_SHA = '52d50ec9ef505873945fd023bcbd9a565f6423efebd10a09a852f2a05d210893'
PYTHON = '/usr/bin/python3'
PYTHON_SHA = 'f7ad87c414fc6a5126571b2ecca19351119ac10e54d0539de6a0a9300d81087f'
BOOTSTRAP = 'u:r:trillionnium_owner_open_bootstrap:s0'
KEYS = ('session_id', 'profile_id', 'task_id', 'turn_id', 'turn_stream_id')
PROTOCOL = 'trillionnium.owner-open.provider-jsonl.v1'
GONE = (errno.ENOENT, errno.ESRCH)


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _x: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def stable(path, limit, mode=None):
    path = Path(path)
    need(path.parent.resolve(strict=True) == path.parent, 'noncanonical source parent')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             0 <= before.st_size <= limit and before.st_uid == before.st_gid == 0,
             'source metadata differs')
        if mode is not None:
            need(stat.S_IMODE(before.st_mode) == mode, 'source mode differs')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(limit + 1)
        after, named = os.fstat(fd), path.lstat()
        fields = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        need(len(raw) == before.st_size and all(getattr(before,k) == getattr(after,k) == getattr(named,k)
             for k in fields), 'source changed during observation')
        return raw, (before.st_dev, before.st_ino)
    finally:
        os.close(fd)


def proc_bytes(pid, leaf, limit=65536):
    with (PROC/str(pid)/leaf).open('rb') as stream:
        raw = stream.read(limit + 1)
    need(len(raw) <= limit, 'proc read bound')
    return raw


def process(pid):
    raw = proc_bytes(pid, 'stat').decode()
    need(int(raw.split(' ', 1)[0]) == pid, 'proc PID view mismatch')
    tail = raw.rsplit(') ', 1)[1].split()
    need(len(tail) >= 20 and tail[0] not in ('Z', 'X'), 'process no longer live')
    status = {row.split(':',1)[0]:row.split(':',1)[1].strip()
              for row in proc_bytes(pid,'status').decode().splitlines() if ':' in row}
    domain = proc_bytes(pid, 'attr/current', 512)
    if domain.endswith(b'\0') or domain.endswith(b'\n'):
        domain = domain[:-1]
    need(not any(x in domain for x in (b'\0',b'\n',b'\r')), 'malformed process domain')
    cmdline = proc_bytes(pid, 'cmdline')
    need(cmdline.endswith(b'\0'), 'unterminated process command line')
    return dict(pid=pid, ppid=int(tail[1]), pgrp=int(tail[2]), sid=int(tail[3]),
                start_ticks=int(tail[19]), state=tail[0], domain=domain.decode('ascii'),
                uid=list(map(int,status['Uid'].split())), gid=list(map(int,status['Gid'].split())),
                no_new_privs=int(status['NoNewPrivs']),
                exe=os.readlink(PROC/str(pid)/'exe'),
                argv=[arg.decode('utf-8') for arg in cmdline[:-1].split(b'\0')])


def identity(row):
    return [row[key] for key in ('pid','pgrp','sid','start_ticks')]


def fd_links(pid):
    result = {}
    directory = PROC/str(pid)/'fd'
    names = list(directory.iterdir())
    need(len(names) <= 8192, 'process fd bound')
    for path in names:
        try:
            result[int(path.name)] = os.readlink(path)
        except OSError as error:
            if error.errno not in GONE:
                raise
    return result


def sockets(links):
    return {match.group(1) for target in links.values()
            if (match := re.fullmatch(r'socket:\[([0-9]+)\]', target))}


def tcp_rows():
    raw = (PROC/'net/tcp').read_bytes()
    need(len(raw) <= 4*1024*1024, 'TCP table bound')
    rows = [line.split() for line in raw.decode('ascii').splitlines()[1:]]
    need(all(len(row) >= 10 for row in rows), 'TCP table row differs')
    return rows


def accepted_pair(provider_pid):
    """Only a server-owned ESTABLISHED socket counts, never a pending connect."""
    rows = tcp_rows()
    owner = sockets(fd_links(provider_pid))
    local = '0100007F:'+format(PORT, '04X')
    servers = [row for row in rows if row[1] == local and row[3] == '01' and row[9] in owner]
    need(len(servers) == 1, 'exactly one provider-owned accepted connection required')
    server = servers[0]
    need(server[2].startswith('0100007F:'), 'client is not IPv4 loopback')
    peers = [row for row in rows if row[1] == server[2] and row[2] == server[1] and row[3] == '01']
    need(len(peers) == 1 and peers[0][9] != '0', 'unique reverse TCP peer required')
    return dict(server_inode=server[9], client_inode=peers[0][9],
                server_address=server[1], client_address=server[2])


def process_digest(pid):
    digest = hashlib.sha256(); count = 0
    with (PROC/str(pid)/'exe').open('rb') as stream:
        for block in iter(lambda:stream.read(1048576), b''):
            count += len(block); need(count <= 32*1024*1024, 'process executable size bound')
            digest.update(block)
    return digest.hexdigest()


def owned_pipes(carrier, parent):
    child_fds, parent_fds = fd_links(carrier), fd_links(parent)
    pairs = {}
    for fd in (0,1,2):
        pipe = child_fds.get(fd, '')
        need(re.fullmatch(r'pipe:\[[0-9]+\]', pipe), 'relay stdio is not an owned pipe')
        owners = [n for n, value in parent_fds.items() if value == pipe]
        need(owners, 'native parent no longer owns relay pipe peer')
        pairs[str(fd)] = dict(pipe=pipe, parent_fds=owners)
    need(len({value['pipe'] for value in pairs.values()}) == 3, 'relay pipes are aliased')
    return pairs


def revalidate_transport_edges(provider, carrier, parent, pair, pipes):
    need(accepted_pair(provider)==pair and pair['client_inode'] in sockets(fd_links(carrier)),
         'relay socket ownership changed during observation')
    need(owned_pipes(carrier,parent)==pipes, 'native parent/relay pipe peers changed during observation')


def open_original_streams(provider_pid, run):
    files = {}
    for name in ('provider-in.jsonl', 'provider-out.jsonl'):
        _raw, wanted = stable(run/name, 16*1024*1024, 0o600)
        matches = []
        for fd in fd_links(provider_pid):
            try:
                info = os.stat(PROC/str(provider_pid)/'fd'/str(fd))
            except OSError as error:
                if error.errno in GONE:
                    continue
                raise
            if (info.st_dev,info.st_ino) == wanted:
                matches.append(fd)
        need(matches, 'provider is not holding current original stream open')
        files[name] = dict(device=wanted[0], inode=wanted[1], provider_fds=matches)
    return files


def _observe_active(bound):
    need(set(bound) == {'schema','expected_boot','scope','owner_request_sha256','run',
                        'provider_identity','source_seal_sha256','configuration_sha256','runtime_binding'}, 'binding fields differ')
    need(bound['schema'] == 'hepta.r10.native-carrier-observation-binding.v1', 'binding schema')
    need(isinstance(bound['scope'],dict) and set(bound['scope']) == set(KEYS) and
         all(isinstance(v,str) and 0<len(v.encode())<=256 and '\0' not in v for v in bound['scope'].values()), 'scope invalid')
    for key in ('owner_request_sha256','source_seal_sha256','configuration_sha256'):
        need(re.fullmatch('[0-9a-f]{64}',bound[key]), 'digest format')
    runtime=active.current(bound['runtime_binding'],bound['expected_boot'])
    release_pins=bound['runtime_binding']['release_pins']
    need(all(bound[k]==release_pins[k] for k in ('source_seal_sha256','configuration_sha256'))
         and bound['provider_identity']==runtime['ready']['roles']['provider']['identity'],
         'exact selected v150-r10-r1 source and actual provider generation required')
    need(re.fullmatch('[0-9]{8}-[0-9]{6}-[0-9a-f]{32}',bound['run']), 'run name differs')
    need(len(bound['provider_identity']) == 4 and all(type(n) is int and n>1 for n in bound['provider_identity']), 'provider identity invalid')
    boot = (PROC/'sys/kernel/random/boot_id').read_text().strip()
    need(boot == bound['expected_boot'], 'boot differs')
    need(os.getuid() == os.geteuid() == 0 and os.readlink(PROC/'1/exe') == '/system/bin/init', 'native root proc view required')
    init_domain = proc_bytes(1, 'attr/current', 512)
    need(init_domain in (b'u:r:init:s0', b'u:r:init:s0\0', b'u:r:init:s0\n'), 'native init domain differs')
    need((PROC/'1/root/sys/fs/selinux/enforce').read_bytes() in (b'1',b'1\n'), 'SELinux not enforcing')
    relay_raw, _ = stable(RELAY, 65536, 0o555)
    config_raw, _ = stable(RELAY_CONFIG, 65536, 0o444)
    need(sha(relay_raw) == RELAY_SHA and sha(config_raw) == RELAY_CONFIG_SHA, 'installed relay/config source pin differs')
    relay_config = strict(config_raw)
    need(relay_config['host'] == '127.0.0.1' and relay_config['port'] == PORT, 'relay endpoint differs')
    seal_raw, _ = stable(BASE/'provider-r10-r1/SOURCE-SEAL-v150-r10.json', 262144, 0o600)
    need(sha(seal_raw) == bound['source_seal_sha256'], 'provider source seal differs')
    seal = strict(seal_raw)
    need(seal['configuration']['sha256'] == bound['configuration_sha256'], 'configuration seal differs')
    live_config, _ = stable(BASE/'local-config-r10-r1.json', 262144, 0o600)
    need(sha(live_config) == bound['configuration_sha256'], 'live configuration changed')
    live_service, _ = stable(BASE/'PHONE-SERVICE-INPUTS-v150-r10-r1.json', 262144, 0o600)
    need(sha(live_service)==release_pins['service_inputs_sha256'] and
         seal['phone_service_inputs_sha256']==sha(live_service) and
         strict(live_config)['service_manifest_sha256']==sha(live_service),
         'live service/source/configuration binding differs')
    source_pins = {row['path']:row['sha256'] for row in seal['production_files']}
    need(len(source_pins) == 15, 'production source inventory differs')
    for relative, pin in source_pins.items():
        p = Path(relative)
        need(len(p.parts)==2 and p.parts[0]=='source' and p.suffix=='.py' and '..' not in p.parts, 'unsafe source path')
        raw, _ = stable(BASE/'provider-r10-r1'/p, 262144, 0o600)
        need(sha(raw) == pin, 'production source pin differs')
    ready_raw, _ = stable(BASE/'provider-state/ready.json', 65536, 0o600)
    ready = strict(ready_raw)
    provider_pid = bound['provider_identity'][0]
    need(ready['pid'] == provider_pid and ready['accepting'] is True and ready['workers']==1 and
         ready['port']==PORT and ready['source_sha256']==source_pins['source/daily_phone_local.py'] and
         ready['config_sha256']==bound['configuration_sha256'], 'actual single-worker provider differs')
    provider = process(provider_pid)
    need(identity(provider) == bound['provider_identity'] and provider['domain']=='u:r:magisk:s0' and
         provider['uid']==provider['gid']==[0]*4 and provider['no_new_privs']==0 and
         provider['exe']==PYTHON and process_digest(provider_pid)==PYTHON_SHA, 'provider generation/credentials/image differs')
    run = BASE/'provider-state/evidence'/bound['run']
    incoming, _ = stable(run/'provider-in.jsonl', 16*1024*1024, 0o600)
    need(incoming.endswith(b'\n'), 'current provider input has partial frame')
    start = strict(incoming.splitlines()[0]); turn = start.get('turn',{})
    need(start.get('protocol')==PROTOCOL and start.get('kind')=='turn.start' and
         {k:turn.get(k) for k in KEYS}==bound['scope'] and
         sha(turn['user_input'].encode())==bound['owner_request_sha256'], 'accepted original turn differs')
    claim_key = sha(json.dumps([bound['scope'][k] for k in KEYS[:-1]],separators=(',',':')).encode())
    claim_raw, _ = stable(BASE/'provider-state/evidence/claims'/claim_key, 65536, 0o600)
    claim = strict(claim_raw)
    need(claim.get('state')=='accepted_no_redispatch' and claim.get('identity')==bound['scope'] and
         claim.get('request_sha256')==bound['owner_request_sha256'] and claim.get('run_dir')==str(run), 'claim binding differs')
    need(not (run/'terminal.json').exists() and not (run/'terminal.json').is_symlink(), 'task is already terminal')
    streams = open_original_streams(provider_pid, run)
    pair = accepted_pair(provider_pid)
    candidates = []
    pids = [int(p.name) for p in PROC.iterdir() if p.name.isdecimal()]
    need(len(pids) <= 16384, 'proc census bound')
    for pid in pids:
        try:
            if os.readlink(PROC/str(pid)/'exe') != PYTHON:
                continue
            row = process(pid)
            if row['argv'] not in ([PYTHON,str(RELAY)], [PYTHON,str(RELAY),'--config',str(RELAY_CONFIG)]):
                continue
            if pair['client_inode'] in sockets(fd_links(pid)):
                candidates.append(row)
        except OSError as error:
            if error.errno not in GONE:
                raise
    need(len(candidates) == 1, 'one exact relay owner required')
    carrier = candidates[0]
    need(carrier['pid']==carrier['pgrp'] and carrier['domain']==BOOTSTRAP and
         carrier['uid']==carrier['gid']==[0]*4 and carrier['no_new_privs']==0 and
         process_digest(carrier['pid'])==PYTHON_SHA, 'relay ownership/domain/image differs')
    parent = process(carrier['ppid'])
    need(parent['exe']==HOST and parent['domain']==BOOTSTRAP and parent['uid']==parent['gid']==[0]*4 and
         parent['no_new_privs']==0 and carrier['sid']==parent['sid'] and
         process_digest(parent['pid'])==HOST_SHA, 'native parent generation/image differs')
    argv = parent['argv']
    need(argv.count('--provider')==1 and argv[argv.index('--provider')+1]==str(RELAY), 'native selected relay differs')
    pipes = owned_pipes(carrier['pid'], parent['pid'])
    for before in (provider, carrier, parent):
        after = process(before['pid'])
        need(all(after[k]==before[k] for k in ('pid','ppid','pgrp','sid','start_ticks','domain','uid','gid','no_new_privs','exe','argv')),
             'process changed during observation')
    revalidate_transport_edges(provider_pid,carrier['pid'],parent['pid'],pair,pipes)
    need(open_original_streams(provider_pid,run)==streams, 'original streams changed during observation')
    need(sha(stable(BASE/'provider-state/evidence/claims'/claim_key,65536,0o600)[0])==sha(claim_raw) and
         not (run/'terminal.json').exists() and (PROC/'sys/kernel/random/boot_id').read_text().strip()==boot,
         'turn/boot ended or changed during observation')
    return dict(schema='hepta.r10.native-carrier-observation.v1', state='READ_ONLY_KERNEL_CHAIN_BOUND',
                release_id='v150-r10-r1', release_pins=release_pins,
                runtime_binding_sha256=runtime['binding_sha256'],
                service_inputs_sha256=sha(live_service),
                boot_id=boot, scope=bound['scope'], owner_request_sha256=bound['owner_request_sha256'],
                run=str(run), claim_sha256=sha(claim_raw), provider=provider, carrier=carrier,
                native_parent=parent, socket_pair=pair, pipe_peers=pipes, original_streams=streams,
                observed_monotonic_ns=time.monotonic_ns(), signals_sent=0, socket_connections=0,
                task_submissions=0, native_scope_link='exact accepted claim + open provider original streams + sole accepted socket + native child/pipe chain',
                native_journal_hashes_verified=False, phase_before_or_after_effect_qualified=False,
                signal_eligible_without_immediate_revalidation=False, physical_case_pass=False)


def observe(bound):
    need(isinstance(bound,dict) and 'runtime_binding' in bound and 'expected_boot' in bound,
         'explicit active runtime binding required')
    with active.verified_runtime(bound['runtime_binding'],bound['expected_boot']):
        return _observe_active(bound)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--binding-b64', required=True)
    args = p.parse_args()
    need(len(args.binding_b64)<=64000, 'input bound')
    bound = strict(base64.b64decode(args.binding_b64,validate=True))
    print(json.dumps(observe(bound),sort_keys=True,ensure_ascii=False))


if __name__ == '__main__':
    main()
