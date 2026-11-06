#!/usr/bin/env python3
"""Prepare exact host material, or run five cases in one fresh P4 user namespace.

Default preview does not read input/source plans or write files. Execution has
no namespace-free fallback, no phone route, no model weights and no real key.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time
import traceback
import types

sys.dont_write_bytecode = True
P4 = Path('/home/alex/razr60-local-model-v150')
CLIENT = '/var/lib/trillionnium/owner-open/phone-local-v150/tool_client_r6.py'
SOURCE_SCHEMA = 'hepta.fixed19.r10.host-lifecycle-source-package.v1'
INPUT_SCHEMA = 'hepta.fixed19.r10.host-lifecycle-inputs.v1'
META = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
MAX_FILE = 4*1024*1024
MAX_POOL = 32*1024*1024
MAX_MEMBERS = 2048


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False)+'\n').encode()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def strict(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate JSON key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def path(value, exists=True):
    p = Path(value)
    need(p.is_absolute() and str(p) == value and '..' not in p.parts and '\0' not in value,
        'explicit canonical absolute path required')
    if exists:
        need(p.resolve(strict=True) == p, 'symlinked path rejected')
    else:
        need(p.parent.resolve(strict=True) == p.parent, 'canonical existing parent required')
    return p


def relative(value):
    need(type(value) is str and re.fullmatch(r'[A-Za-z0-9._/-]{1,1024}', value)
        and not value.startswith('/') and all(x not in ('', '.', '..') for x in value.split('/')),
        'canonical relative member required')
    return value


def regular(p, maximum=MAX_FILE):
    p = path(str(p))
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and 0 <= before.st_size <= maximum, 'regular single-link bounded original required')
        chunks, size = [], 0
        while True:
            block = os.read(fd, min(65536, maximum+1-size))
            if not block:
                break
            size += len(block)
            need(size <= maximum, 'original grew beyond bound')
            chunks.append(block)
        raw = b''.join(chunks)
        after, named = os.fstat(fd), p.lstat()
        need(len(raw) == before.st_size and all(getattr(before, k) == getattr(after, k)
            == getattr(named, k) for k in META), 'original changed during read')
        return raw
    finally:
        os.close(fd)


def pin(p, digest, size=None):
    need(type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest), 'explicit SHA256 required')
    raw = regular(p)
    need(sha(raw) == digest and (size is None or len(raw) == size), 'original pin differs: '+str(p))
    return raw


def descriptor(p, raw):
    return {'path': str(p), 'bytes': len(raw), 'sha256': sha(raw)}


def sync_dir(p):
    fd = os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def new_dir(p):
    p = path(str(p), exists=False)
    need(not p.exists() and not p.is_symlink(), 'create-only directory already exists')
    os.mkdir(p, 0o700)
    st = p.lstat()
    need(stat.S_ISDIR(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o700
        and st.st_uid == os.geteuid(), 'new directory is not private and owned')
    sync_dir(p.parent)
    return p


def put(p, raw):
    p = path(str(p), exists=False)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        before = os.fstat(fd)
        data = memoryview(raw)
        while data:
            n = os.write(fd, data)
            need(n > 0, 'short output write')
            data = data[n:]
        os.fsync(fd)
        after, named = os.fstat(fd), p.lstat()
        need((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
            == (named.st_dev, named.st_ino), 'output replaced before publication')
    finally:
        os.close(fd)
    sync_dir(p.parent)
    need(regular(p) == raw, 'new output readback differs')
    return descriptor(p, raw)


def write(p, value):
    return put(p, encoded(value))


def inventory(root, excluded=()):
    rows, skips, total = [], [], 0
    for p in sorted(root.rglob('*')):
        st = p.lstat()
        name = relative(str(p.relative_to(root)))
        need(not stat.S_ISLNK(st.st_mode), 'symlink in retained originals')
        if stat.S_ISDIR(st.st_mode):
            continue
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1, 'special or linked original')
        if name in excluded:
            continue
        if p.name == 'synthetic-only-api.key':
            need(re.fullmatch(r'NEG-0[45789]/config/synthetic-only-api.key', name)
                and stat.S_IMODE(st.st_mode) == 0o600 and st.st_size == 49,
                'unexpected excluded synthetic credential')
            skips.append({'path': name, 'reason': 'synthetic credential; no content or digest retained'})
            continue
        raw = regular(p)
        total += len(raw)
        need(total <= MAX_POOL and len(rows) < MAX_MEMBERS, 'original inventory capacity')
        rows.append({'path': name, 'bytes': len(raw), 'sha256': sha(raw)})
    return rows, skips


def load_package(expected):
    root = path(os.path.abspath(__file__)).parent.parent
    manifest_raw = pin(root/'SOURCE-MANIFEST.json', expected)
    manifest = strict(manifest_raw)
    need(manifest['schema'] == SOURCE_SCHEMA and manifest['physical_case_pass'] is False,
        'source package schema')
    rows = manifest['files']
    names, bodies, total = set(), {}, 0
    for row in rows:
        name = relative(row['path'])
        need(set(row) == {'path','bytes','sha256'} and name not in names, 'source inventory row')
        names.add(name)
        body = pin(root/name, row['sha256'], row['bytes'])
        total += len(body)
        need(total <= MAX_POOL, 'source package total bound')
        bodies[name] = body
    need('source/host_lifecycle.py' in names and 'source/lifecycle_support.py' in names
        and 'source/verify_host_originals.py' in names, 'source entry inventory incomplete')
    runtime = {str(p.relative_to(root)) for p in (root/'source').rglob('*') if p.is_file()}
    need(runtime == {n for n in names if n.startswith('source/')}, 'extra runtime source')
    for p in root.rglob('*'):
        need(not p.is_symlink(), 'source package symlink')
    def module(name):
        m = types.ModuleType('reviewed_'+name)
        m.__file__ = str(root/'source'/(name+'.py'))
        exec(compile(bodies['source/'+name+'.py'], m.__file__, 'exec'), m.__dict__)
        return m
    support = module('lifecycle_support')
    support.HARNESS = root/'source'
    return root, manifest_raw, manifest, support, module


def check_inputs(inputs, expected, H):
    raw = pin(inputs/'INPUT-MANIFEST.json', expected)
    manifest = strict(raw)
    need(manifest['schema'] == INPUT_SCHEMA
        and manifest['state'] == 'EXACT_CURRENT_SOURCE_MATERIAL_FOR_ISOLATED_HOST_ONLY'
        and manifest['phone_calls'] == 0 and manifest['physical_case_pass'] is False
        and manifest['deployment_source_seal_sha256'] is None, 'host-only input identity')
    rows, skipped = inventory(inputs, {'INPUT-MANIFEST.json'})
    need(not skipped and rows == manifest['files'], 'complete input inventory differs')
    sources = strict(regular(inputs/'SOURCE-PINS.json'))
    need(set(sources) == set(H.PRODUCTION_PINS) and len(sources) == 15, 'fixed source15 inventory')
    for name, digest in H.PRODUCTION_PINS.items():
        need(sources[name]['sha256'] == digest, 'fixed current source differs')
        pin(inputs/'provider/source'/name, digest, sources[name]['bytes'])
    for filename, digest in [('production-config.json',H.CONFIG_SHA),
        ('production-service.json',H.SERVICE_SHA),('client/tool_client_r6.py',H.CLIENT_SHA),
        ('original-protocol.json',H.PROTOCOL_SHA)]:
        pin(inputs/filename, digest)
    generation = manifest['host_material_generation']
    seal = strict(pin(inputs/'provider/SOURCE-SEAL.json', generation['host_source_seal_sha256']))
    combo_raw = pin(inputs/'combination.json', generation['host_material_combination_sha256'])
    combo = strict(combo_raw)
    need(seal['schema'] == 'hepta.fixed19.host-only-source-material-seal.v1'
        and seal['deployment_authority'] is False and seal['production_sources'] == sources
        and combo['schema'] == 'hepta.fixed19.host-only-material-combination.v1'
        and combo['host_source_seal_sha256'] == generation['host_source_seal_sha256']
        and combo['configuration_sha256'] == H.CONFIG_SHA and combo['service_inputs_sha256'] == H.SERVICE_SHA
        and combo['client_sha256'] == H.CLIENT_SHA and combo['protocol_sha256'] == H.PROTOCOL_SHA
        and generation['host_material_combination_canonical_sha256'] == sha(canonical(combo)),
        'host material seal or combination differs')
    return raw, manifest


def prepare(args, root, package_raw, package, H):
    source = path(args.production_source_dir)
    raw_sources = {name: pin(source/name, digest) for name,digest in H.PRODUCTION_PINS.items()}
    cfg = pin(path(args.configuration), H.CONFIG_SHA)
    service = pin(path(args.service_inputs), H.SERVICE_SHA)
    client = pin(root/'reference/tool_client_r6.py', H.CLIENT_SHA)
    protocol = pin(root/'reference/original-protocol.json', H.PROTOCOL_SHA)
    for name, raw in raw_sources.items():
        compile(raw, name, 'exec')
    original_cfg = strict(cfg)
    need(original_cfg['max_prompt_bytes'] == 24576 and original_cfg['max_tokens'] == 256
        and original_cfg['executor']['client_sha256'] == H.CLIENT_SHA
        and original_cfg['executor']['timeout_ms'] == 60000,
        'production configuration bounds or client differ')
    output = new_dir(path(args.out, exists=False))
    for name in ('provider','provider/source','client'):
        new_dir(output/name)
    source_pins = {name: {'bytes':len(body),'sha256':sha(body)} for name,body in sorted(raw_sources.items())}
    for name, body in sorted(raw_sources.items()):
        put(output/'provider/source'/name, body)
    for filename, body in [('production-config.json',cfg),('production-service.json',service),
        ('client/tool_client_r6.py',client),('original-protocol.json',protocol)]:
        put(output/filename, body)
    write(output/'SOURCE-PINS.json', source_pins)
    seal = {'schema':'hepta.fixed19.host-only-source-material-seal.v1',
        'production_sources':source_pins,'configuration_sha256':H.CONFIG_SHA,
        'service_inputs_sha256':H.SERVICE_SHA,'source_package_manifest_sha256':sha(package_raw),
        'deployment_authority':False,'physical_case_pass':False,'production_mutations':0}
    seal_desc = write(output/'provider/SOURCE-SEAL.json', seal)
    combination = {'schema':'hepta.fixed19.host-only-material-combination.v1',
        'host_source_seal_sha256':seal_desc['sha256'],'configuration_sha256':H.CONFIG_SHA,
        'service_inputs_sha256':H.SERVICE_SHA,'client_sha256':H.CLIENT_SHA,'protocol_sha256':H.PROTOCOL_SHA,
        'source_package_manifest_sha256':sha(package_raw),'production_imports_or_task_dispatches':0,
        'deployment_combination':False,'physical_case_pass':False}
    combo_desc = write(output/'combination.json', combination)
    rows, skips = inventory(output)
    need(not skips, 'input preparation has unexpected exclusions')
    manifest = {'schema':INPUT_SCHEMA,'state':'EXACT_CURRENT_SOURCE_MATERIAL_FOR_ISOLATED_HOST_ONLY',
        'files':rows,'source_package_manifest_sha256':sha(package_raw),
        'host_material_generation':{'host_source_seal_sha256':seal_desc['sha256'],
            'host_material_combination_sha256':combo_desc['sha256'],
            'host_material_combination_canonical_sha256':sha(canonical(combination))},
        'deployment_source_seal_sha256':None,'future_deployment_binding_qualified':False,
        'phone_calls':0,'model_requests':0,'physical_case_pass':False,
        'bound_server_cleanup_branch_qualified':False}
    desc = write(output/'INPUT-MANIFEST.json', manifest)
    check_inputs(output, desc['sha256'], H)
    return {'state':'HOST_INPUT_MATERIAL_PREPARED','input_manifest':desc,
        'host_material_generation':manifest['host_material_generation'],
        'production_source_count':15,'phone_calls':0,'case_runs':0,'physical_case_pass':False}


def namespace_argv(root, inputs, out, server, counter):
    return ['/usr/bin/bwrap','--unshare-user','--uid','0','--gid','0','--unshare-pid',
        '--unshare-net','--unshare-ipc','--unshare-uts','--die-with-parent','--new-session',
        '--ro-bind','/usr','/usr','--symlink','usr/lib','/lib','--symlink','usr/lib64','/lib64',
        '--symlink','usr/bin','/bin','--symlink','usr/sbin','/sbin','--proc','/proc','--dev','/dev',
        '--tmpfs','/tmp','--dir','/var/lib/trillionnium/owner-open/phone-local-v150',
        '--ro-bind',str(inputs),'/suite','--ro-bind',str(root/'source'),'/harness',
        '--bind',str(out),'/work','--ro-bind',str(inputs/'client/tool_client_r6.py'),CLIENT,
        '--clearenv','--setenv','PATH','/usr/bin:/bin','--setenv','LANG','C.UTF-8',
        '--setenv','PYTHONDONTWRITEBYTECODE','1','--chdir','/work','--cap-drop','ALL','--',
        '/usr/bin/python3','-I','-B','/harness/run_fault_cases.py','--execute-once',
        '--server-sha256',server,'--counter-sha256',counter]


def execute(args, root, package_raw, package, H, module):
    need(sys.platform.startswith('linux'), 'P4 Linux namespace execution required')
    inputs = path(args.inputs)
    out = path(args.out, exists=False)
    need(P4 in root.parents and P4 in inputs.parents and P4 in out.parents,
        'execution paths must be inside the reviewed P4 project root')
    need(out not in root.parents and out not in inputs.parents and root not in out.parents
        and inputs not in out.parents, 'writable output cannot contain or be inside readonly inputs')
    before_raw, before = check_inputs(inputs, args.input_manifest_sha256, H)
    need(before['source_package_manifest_sha256'] == sha(package_raw), 'input/source package generation differs')
    need(H.proc(os.getpid()) is not None and H.proc(os.getpid())['pid'] == os.getpid()
        and H.proc(os.getpid())['ppid'] == os.getppid(), 'outer procfs namespace is incoherent')
    out = new_dir(out)
    H.WORK = out
    start = time.monotonic()
    H.SUITE_DEADLINE = start+105
    env = {'host_uid':os.getuid(),'host_gid':os.getgid(),'host_pid':os.getpid(),
        'host_netns':os.readlink('/proc/self/ns/net'),'host_mntns':os.readlink('/proc/self/ns/mnt'),
        'host_pidns':os.readlink('/proc/self/ns/pid'),'input_manifest_sha256':sha(before_raw),
        'source_manifest_sha256':sha(package_raw),'output_root':str(out),'package_root':str(root),
        'input_root':str(inputs),'phone_calls':0,'real_model_requests':0}
    write(out/'OUTER-ENV.json', env)
    write(out/'INPUT-PINS-BEFORE.json', before['files'])
    server = sha(pin(root/'source/fixture_server.py',
        '4848e66e94115f64baddc47b575aab53f34d947e7cebc89173f604870504a049'))
    counter = sha(pin(root/'source/counter_effect.py',
        '53aa97adbba5ad9df7fe9e21a00bd5fadcf41aa3d2211521826e6dd00b80f59b'))
    argv = namespace_argv(root,inputs,out,server,counter)
    write(out/'EXECUTION-INTENT.json', {'argv':argv,'maximum_namespace_starts':1,
        'inner_deadline_seconds':90,'outer_capture_deadline_seconds':105,
        'automatic_retry':False,'namespace_free_fallback':False,'phone_calls':0,'real_model_requests':0})
    child, error, joined = None, None, None
    try:
        child = H.Owned('namespace',argv,out)
        joined = child.join(timeout=105)
    except BaseException as ex:
        error = {'type':type(ex).__name__,'message':str(ex),'traceback':traceback.format_exc()}
    finally:
        for owned in reversed(H.OWNED):
            if not owned.joined:
                try:
                    owned.join(timeout=3,stop=True)
                except BaseException as ex:
                    error = error or {'type':type(ex).__name__,'message':'owned namespace cleanup unconfirmed: '+str(ex)}
    after_raw, after = check_inputs(inputs,args.input_manifest_sha256,H)
    need(after_raw == before_raw and after == before, 'input originals changed during namespace execution')
    # Revalidate all runtime source bytes; no replacement is silently accepted.
    load_package(sha(package_raw))
    write(out/'INPUT-PINS-AFTER.json', after['files'])
    inner = strict(regular(out/'RESULT.json')) if (out/'RESULT.json').is_file() else None
    p = child.p if child is not None else None
    result = {'schema':'hepta.isolated-host-fault-outer.v150.r10.1',
        'state':'ORIGINAL_NAMESPACE_JOINED' if joined is not None else 'NAMESPACE_OUTCOME_UNVERIFIED_NO_RETRY',
        'original_argv':argv,'original_pid':p.pid if p is not None else None,
        'original_identity':child.identity if child is not None else None,
        'returncode':p.returncode if p is not None else None,'actual_join':joined,'error':error,
        'elapsed_seconds':time.monotonic()-start,'source_input_pins_preserved':True,
        'inner_status':inner.get('status') if inner else None,'phone_calls':0,'real_model_requests':0,
        'production_changes':0,'physical_case_pass':False,'deployment_binding_qualified':False,
        'automatic_retry':False,'namespace_free_fallback':False}
    result_desc = write(out/'OUTER-RESULT.json', result)
    rows, skips = inventory(out)
    manifest_desc = write(out/'ORIGINAL-FILES.json', {'schema':'hepta.fixed19.host-lifecycle-original-inventory.v1',
        'files':rows,'excluded':skips,'files_count':len(rows),'bytes':sum(r['bytes'] for r in rows),
        'input_manifest_sha256':sha(before_raw),'source_manifest_sha256':sha(package_raw),
        'layer':'host_isolated','physical_case_pass':False})
    qualification = module('verify_host_originals').verify(out,inputs,sha(before_raw),
        manifest_desc['sha256'],root,sha(package_raw),H)
    proof_desc = write(out/'HOST-VERIFICATION.json', qualification)
    return {'state':'HOST_ORIGINALS_VERIFIED','outer_result':result_desc,'original_inventory':manifest_desc,
        'host_verification':proof_desc,'host_cases':qualification['host_cases'],
        'phone_calls':0,'physical_case_pass':False,'fixed19_whole_cases_closed':False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    modes = p.add_mutually_exclusive_group()
    modes.add_argument('--prepare-inputs-once',action='store_true')
    modes.add_argument('--execute-once',action='store_true')
    modes.add_argument('--verify-originals',action='store_true')
    p.add_argument('--source-manifest-sha256')
    p.add_argument('--production-source-dir')
    p.add_argument('--configuration')
    p.add_argument('--service-inputs')
    p.add_argument('--inputs')
    p.add_argument('--input-manifest-sha256')
    p.add_argument('--evidence')
    p.add_argument('--original-files-sha256')
    p.add_argument('--out')
    args = p.parse_args()
    if not (args.prepare_inputs_once or args.execute_once or args.verify_originals):
        print(json.dumps({'state':'SOURCE_ONLY_PREVIEW','cases':['NEG-04','NEG-05','NEG-07','NEG-08','NEG-09'],
            'layer':'host_isolated','phone_calls':0,'case_runs':0,'physical_case_pass':False,
            'required_P4_root':str(P4),'inner_seconds':90,'outer_seconds':105,'automatic_retry':False}))
        return 0
    os.umask(0o077)
    root,raw,manifest,H,module = load_package(args.source_manifest_sha256)
    if args.prepare_inputs_once:
        result = prepare(args,root,raw,manifest,H)
    elif args.execute_once:
        result = execute(args,root,raw,manifest,H,module)
    else:
        inputs = path(args.inputs)
        check_inputs(inputs,args.input_manifest_sha256,H)
        result = module('verify_host_originals').verify(path(args.evidence),inputs,
            args.input_manifest_sha256,args.original_files_sha256,root,sha(raw),H)
    print(json.dumps(result,sort_keys=True,ensure_ascii=False))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'state':'HOST_ONLY_UNVERIFIED_NO_RETRY','error_type':type(error).__name__,
            'error':str(error),'automatic_retry':False,'phone_calls':0,'physical_case_pass':False}),file=sys.stderr)
        raise SystemExit(1)
