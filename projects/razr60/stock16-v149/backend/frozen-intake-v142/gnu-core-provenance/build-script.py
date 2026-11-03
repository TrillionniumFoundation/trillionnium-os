"""Build the proposed core with a private measured copy of existing GNU inputs.

The actual candidate runtime is Ubuntu GLIBC 2.39, independently read from
the original 931-entry verified EROFS. No global tool/runtime modification.
"""
import datetime, hashlib, json, os, pathlib, re, shlex, shutil, subprocess, time

BASE=pathlib.Path(__file__).resolve().parent
SOURCE=BASE/'proposed-4b687742'
ROOT=BASE/'gnu-actual239-r1'
ROOT.mkdir(mode=0o700,exist_ok=False)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def inventory(root):
    return {str(p.relative_to(root)):{'bytes':p.stat().st_size,'sha256':sha(p.read_bytes())}
            for p in sorted(root.rglob('*')) if p.is_file()}
def write(name,value):(ROOT/name).write_text(json.dumps(value,indent=2)+'\n')
def run(label,argv,**kwargs):
    start=time.monotonic();p=subprocess.run(argv,capture_output=True,timeout=kwargs.pop('timeout',20),**kwargs)
    (ROOT/(label+'.stdout')).write_bytes(p.stdout);(ROOT/(label+'.stderr')).write_bytes(p.stderr)
    row={'label':label,'argv':argv,'returncode':p.returncode,'elapsed_seconds':time.monotonic()-start,
         'stdout_sha256':sha(p.stdout),'stderr_sha256':sha(p.stderr)}
    records.append(row);print(json.dumps(row),flush=True);return p
records=[]
rustsys=pathlib.Path(subprocess.check_output(['rustc','--print','sysroot'],text=True).strip()).resolve()
cargo=(rustsys/'bin/cargo').resolve();rustc=(rustsys/'bin/rustc').resolve()
target='aarch64-unknown-linux-gnu'
gcc=pathlib.Path('/usr/bin/aarch64-linux-gnu-gcc-13')
gnu=ROOT/'gnu-sysroot'
(gnu/'usr/bin').mkdir(parents=True)
shutil.copytree('/usr/aarch64-linux-gnu',gnu/'usr/aarch64-linux-gnu',symlinks=False)
shutil.copytree('/usr/lib/gcc-cross/aarch64-linux-gnu/13',gnu/'usr/lib/gcc-cross/aarch64-linux-gnu/13',symlinks=False)
shutil.copy2(gcc,gnu/'usr/bin/aarch64-linux-gnu-gcc-13')
std=ROOT/'rust-sysroot/lib/rustlib'/target
std.parent.mkdir(parents=True)
shutil.copytree(rustsys/'lib/rustlib'/target,std,symlinks=False)
original_std=inventory(rustsys/'lib/rustlib'/target)
assert inventory(std)==original_std
gccdir=gnu/'usr/lib/gcc-cross/aarch64-linux-gnu/13'
binutils=gnu/'usr/aarch64-linux-gnu/bin'
wrapper=ROOT/'target-linker.sh'
wrapper.write_text('#!/bin/sh\nset -eu\n'
    +'GCC_EXEC_PREFIX='+shlex.quote(str(gnu/'usr/lib/gcc-cross')+'/')+'\n'
    +'COMPILER_PATH='+shlex.quote(str(gccdir)+':'+str(binutils))+'\n'
    +'LIBRARY_PATH='+shlex.quote(str(gccdir)+':'+str(gnu/'usr/aarch64-linux-gnu/lib'))+'\n'
    +'export GCC_EXEC_PREFIX COMPILER_PATH LIBRARY_PATH\n'
    +'printf "%s\\0" "$@" >> '+shlex.quote(str(ROOT/'actual-target-link-argv.nul'))+'\n'
    +'exec '+shlex.quote(str(gnu/'usr/bin/aarch64-linux-gnu-gcc-13'))
    +' --sysroot='+shlex.quote(str(gnu))+' -B'+shlex.quote(str(gccdir)+'/')
    +' -B'+shlex.quote(str(binutils)+'/')+' "$@"\n')
wrapper.chmod(0o700)
gnu_before=inventory(gnu)
tools={str(p):{'bytes':p.stat().st_size,'sha256':sha(p.read_bytes())} for p in
       [cargo,rustc,pathlib.Path('/usr/bin/x86_64-linux-gnu-gcc-13'),pathlib.Path('/usr/bin/qemu-aarch64-static'),
        pathlib.Path('/usr/bin/aarch64-linux-gnu-readelf'),wrapper]}
write('tool-inputs.json',{'tools':tools,'private_GNU_inputs':gnu_before,'private_target_std':original_std,
                         'original_target_std_copied_byte_exact':True,
                         'actual_candidate_runtime_GLIBC':'2.39; Ubuntu GLIBC 2.39-0ubuntu8',
                         'not_claimed_as_original_GCC12_or_Bookworm_toolchain':True})
for label,argv in [('rust-version',[str(rustc),'-Vv']),('cargo-version',[str(cargo),'-V']),
                   ('target-gcc-version',[str(wrapper),'--version']),
                   ('target-gcc-search',[str(wrapper),'-print-search-dirs']),
                   ('target-gcc-ld',[str(wrapper),'-print-prog-name=ld'])]:
    p=run(label,argv);assert p.returncode==0,p.stderr
assert str(binutils) in (ROOT/'target-gcc-ld.stdout').read_text()
private_cargo=ROOT/'cargo-home';private_cargo.mkdir()
original_cargo=pathlib.Path(os.environ.get('CARGO_HOME',str(pathlib.Path.home()/'.cargo')))
(private_cargo/'registry').symlink_to((original_cargo/'registry').resolve(),target_is_directory=True)
env={k:v for k,v in os.environ.items() if k not in ('RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER',
    'CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER','CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS','GCC_EXEC_PREFIX',
    'COMPILER_PATH','LIBRARY_PATH','LD_LIBRARY_PATH','CC','CXX','AR','CARGO_TARGET_DIR','CARGO_HOME')}
env.update(PATH='/usr/bin:/bin',CARGO_HOME=str(private_cargo),CARGO_TARGET_DIR=str(ROOT/'target'),
           CARGO_NET_OFFLINE='true',CARGO_INCREMENTAL='0',CARGO_BUILD_JOBS='4',RUSTC=str(rustc),
           CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=str(wrapper),
           CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS='--sysroot='+str(ROOT/'rust-sysroot'))
lock_before=sha((SOURCE/'Cargo.lock').read_bytes())
command=[str(cargo),'build','--release','--frozen','--locked','--offline','--target',target,
         '-p','trillionnium-owner-open-host','--bin','trillionnium-owner-open-r5-core']
build=run('actual-GNU-core-build',command,cwd=SOURCE,env=env,timeout=180)
assert build.returncode==0,build.stderr[-5000:]
assert sha((SOURCE/'Cargo.lock').read_bytes())==lock_before
assert inventory(gnu)==gnu_before and inventory(std)==original_std
for path,ref in tools.items():assert sha(pathlib.Path(path).read_bytes())==ref['sha256']
binary=ROOT/'target'/target/'release/trillionnium-owner-open-r5-core'
elf=run('actual-core-ELF',['/usr/bin/aarch64-linux-gnu-readelf','-h','-l','-d','-V',str(binary)])
assert elf.returncode==0
text=elf.stdout.decode()
assert 'AArch64' in text and 'Requesting program interpreter: /lib/ld-linux-aarch64.so.1' in text
needed=re.findall(r'Shared library: \[([^]]+)\]',text)
libs=BASE/'actual-bookworm-public-libs'  # Historical local folder name; bytes prove actual GLIBC2.39.
actual_manifest=json.loads((libs/'manifest.json').read_text())
actual={pathlib.Path(name).name:libs/name for name in actual_manifest['files']}
for name,ref in actual_manifest['files'].items():assert sha((libs/name).read_bytes())==ref['sha256']
provided={}
for name,path in actual.items():
    version=subprocess.check_output(['/usr/bin/aarch64-linux-gnu-readelf','-V',str(path)],text=True)
    definitions=version.split('Version definition section',1)[1].split('Version needs section',1)[0]
    provided[name]=set(re.findall(r'Name: (\S+)',definitions))
needs={};current=None
for line in text.split('Version needs section',1)[1].splitlines():
    member=re.search(r'File: (\S+)\s+Cnt:',line)
    if member:current=member[1];needs[current]=set()
    version=re.search(r'Name: (\S+)',line)
    if version and current:needs[current].add(version[1])
assert set(needed)<=actual.keys()
assert all(name in provided and versions<=provided[name] for name,versions in needs.items()),needs
glibc=max(tuple(map(int,m.split('.'))) for versions in needs.values() for v in versions
          if (m:=v.removeprefix('GLIBC_'))!=v and re.fullmatch(r'[0-9.]+',m))
assert glibc <= (2,39)
loader=libs/'lib/ld-linux-aarch64.so.1'
library_path=libs/'usr/lib/aarch64-linux-gnu'
qemu=['/usr/bin/qemu-aarch64-static',str(loader),'--library-path',str(library_path),str(binary)]
helped=run('actual-runtime-QEMU-core-help',qemu+['--help'],timeout=15)
assert helped.returncode==0 and b'Usage:' in helped.stdout
scope={'session_id':'session-gnu-proof','profile_id':'owner-open','task_id':'task-gnu-proof','turn_id':'turn-gnu-proof'}
scope['turn_stream_id']='r5-stream-'+sha(json.dumps({'schema':'trillionnium.owner-open.turn-stream.v1',**scope},sort_keys=True,separators=(',',':')).encode())
request={'kind':'turn.cancel','seq':1,'direction':'client_to_host','payload':scope,
         'broker_request_id':'gnu-proof:cancel1','broker_request_sha256':'a'*64,'broker_request_upstream_seq':19}
probe=run('actual-runtime-QEMU-inactive-control',qemu+['--provider','/bin/true'],input=(json.dumps(request)+'\n').encode(),timeout=15)
assert probe.returncode==0
frames=[json.loads(line)for line in probe.stdout.splitlines()]
assert len(frames)==1 and frames[0]['kind']=='host.error' and frames[0]['payload']['code']=='no_active_turn'
assert frames[0]['broker_request_id']==request['broker_request_id'] and frames[0]['broker_request_upstream_seq']==19
record={'schema':'razr.r11r4.GNU-core-crossbuild-actual-runtime-host-proof.v1',
 'state':'ACTUAL_AARCH64_GNU_CORE_BUILT_VERSION_NEEDS_SATISFIED_BY_ORIGINAL_RUNTIME_QEMU_HELP_AND_CONTROL_PASS',
 'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'binary':{'path':str(binary),'bytes':binary.stat().st_size,'sha256':sha(binary.read_bytes())},
 'source_commit_baseline':'4b687742fca939bc32122857f21067ec28d30a23',
 'production_source_sha256':sha((SOURCE/'apps/trillionnium-owner-open-host/src/bin/r5_control_host_v4/process.rs').read_bytes()),
 'Cargo_lock_sha256_unchanged':lock_before,'GNU_private_tree_and_target_std_unchanged':True,
 'actual_runtime_origin':actual_manifest['origin_actual_rootfs'],
 'actual_runtime_libc_sha256':actual_manifest['files']['usr/lib/aarch64-linux-gnu/libc.so.6']['sha256'],
 'actual_runtime_GLIBC':'2.39, Ubuntu GLIBC 2.39-0ubuntu8, not Bookworm',
 'new_ELF_max_needed_GLIBC':'.'.join(map(str,glibc)),
 'new_ELF_NEEDED':needed,'new_ELF_version_needs':{k:sorted(v)for k,v in needs.items()},
 'all_version_needs_present_in_actual_original_public_runtime_ELFs':True,
 'QEMU_help_and_exact_inactive_control_pass':True,'records':records,
 'phone_operations':0,'model_generations':0,'global_installs':0,'actual_P1_pass':False,
 'limits':['Host/QEMU startup and protocol evidence only; native Android candidate still requires full offline binding and actual phone qualification.',
           'Measured private existing GNU13.3 and official installed Rust1.95 inputs, not the old GCC12 closure.',
           'Cargo registry is existing local immutable content selected by frozen lockfile; no network fetch.']}
write('build-and-actual-runtime-proof.json',record)
print(json.dumps({'state':record['state'],'binary':record['binary'],'GLIBC_needed':record['new_ELF_max_needed_GLIBC']}),flush=True)
