#!/usr/bin/env python3
"""Freshly rebuild the original UI-Venus ordinary-App worker on macOS.

The public Code20 manifest is distinct from the private device-build manifest.
Only an exact whole-file match creates the original-assembler runtime directory.
The preserved historical receipt and this new build's receipt remain separate.
No download, APK, deployment, phone, model inference, or pin change occurs here.
"""
from __future__ import annotations
import argparse, hashlib, importlib.util, json, os, platform, shutil, subprocess, sys, time
from pathlib import Path

APP_SHA = '1873ca6ecf998b7f3d3e447de2c9af5004c53c870042e2faef28be94265b40f4'
MNN_REBUILD_SHA = '961594375f7a8c6967426695b38f478106c09fa02e8c60b52eda3061f816d65d'
MNN_TRANSFER_SHA = '75c75071b23a5987fdc9d30c0da8e75d7c857d8a59eb1315b0d673d616e9461b'
COMPILER_QUALIFIER_SHA = '4a20e508438286517659b51ed27829d64dfdf6ee8d22967d6d970ad0a602ae5f'
NATIVE_BUILDER_SHA = '8ffbf2f722cc7279d7495ef96c62fe1b60fe9463f2b29e7e9fa396f190ed112d'
NATIVE_MANIFEST_SHA = '8fcdc6c8edb378314f2afc74c574a2fd1037ccf49c8741484c9c484037666413'
ORIGINAL_RECEIPT_SHA = '3dac4c0e91bd9c088e7330394953f6df74596feff04c7e815672ee8d3392e705'
WORKER = 'libhepta_ui_venus_runner.so'
WORKER_BYTES = 58144
WORKER_SHA = '5fa2dcae05fb649157d96481c5890c157301c76dab3522fcabcbe01b9b0d8551'
DRIVER_SHA = 'cf2d40be93fb6051d3a66f5d6bdd24ccbe6595913040460f3607a241d562af76'
SOURCE_PROPERTIES_SHA = '84bef2c605bb263571c299f1eef3307ff58f741710f8cce514cb525b28567f41'
REMOVED_ENV = ('CC','CXX','CPP','AS','AR','CFLAGS','CXXFLAGS','CPPFLAGS','LDFLAGS',
 'LD_PRELOAD','LD_LIBRARY_PATH','CPATH','C_INCLUDE_PATH','CPLUS_INCLUDE_PATH',
 'LIBRARY_PATH','SDKROOT','MACOSX_DEPLOYMENT_TARGET','PYTHONPATH','PYTHONSTARTUP')
HERE = Path(__file__).resolve().parent

def require(value, reason):
    if value is not True:
        raise ValueError(reason)

def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024), b''):
            digest.update(block)
    return digest.hexdigest()

def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

def dependencies():
    paths = {
      'rebuild': (HERE.parent/'mobimind-runtime-rebuild-v8/rebuild_exact_runtime.py', MNN_REBUILD_SHA),
      'transfer': (HERE.parent/'mobimind-ci-host-split-v8/verify_ci_runtime_bundle.py', MNN_TRANSFER_SHA),
      'compiler': (HERE.parent/'mobimind-ci-host-split-v8/qualify_macos_compiler.py', COMPILER_QUALIFIER_SHA)}
    for path, expected in paths.values():
        require(path.resolve(strict=True) == path and sha(path) == expected, 'pinned shared CI helper changed')
    return module(paths['rebuild'][0], 'source20_public_mnn_rebuild'), module(paths['transfer'][0], 'source20_public_transfer')

def verify_frozen_source(root):
    rebuild, _ = dependencies()
    require(rebuild.APP_MANIFEST_SHA == APP_SHA, 'shared source pin differs')
    return rebuild.verify_frozen_source(root)

def runtime_api(app):
    sys.path.insert(0, str(app/'tools'))
    return module(app/'tools/verify_ui_venus_runtime.py', 'public_ui_venus_runtime')

def check_native_receipt(receipt, app, pins):
    generation = json.loads((app/'provenance/ui-venus-app-r1/native-worker/SOURCE-GENERATION.json').read_bytes())
    expected = {
      'schema':'hepta.ui-venus.app-native-android-build.v1',
      'actual_ndk_revision':'28.1.13356709',
      'compiler_sha256':DRIVER_SHA,
      'source_properties_sha256':SOURCE_PROPERTIES_SHA,
      'source_generation_sha256':pins['source_generation_sha256'],
      'worker_source_sha256':pins['core_source_sha256'],
      'wrapper_source_sha256':pins['wrapper_source_sha256'],
      'entry_guard_sha256':pins['entry_guard_sha256'],
      'sdk_source_commit':pins['sdk_source_commit'],
      'llama_source_commit':pins['llama_source_commit'],
      'build_helper_sha256':NATIVE_BUILDER_SHA,
      'sdk_runtime_pins_sha256':sha(app/'provenance/ui-venus-app-r1/native-worker/tools/sdk-runtime-pins.json'),
      'original_core_byte_unchanged':False,'original_shell_candidate_modified':False,
      'only_model_identity_literals_changed':True,'profile':pins['model_profile'],
      'runtime_core_source_sha256':pins['runtime_core_source_sha256'],
      'baseline_app_source_generation_sha256':pins['baseline_app_source_generation_sha256'],
      'full_multimodal_token_admission_proven':False,'no_context_shift_proven':False,
      'same_directory_bootstrap_unchanged':True,'context_tokens':8192,'max_tokens':1024,
      'deadline_ms':300000,'enable_thinking':True,
      'android_executed':False,'model_inference_performed':False,'ordinary_app_qualified':False,
      'dispatcher_connected':False,'phone_contacted':False,'installed_runtime_modified':False}
    for key, value in expected.items():
        require(type(receipt.get(key)) is type(value) and receipt[key] == value, 'new native build receipt differs: '+key)
    member = pins['worker']
    require(receipt.get('worker') == {
      'name':WORKER,'bytes':WORKER_BYTES,'sha256':WORKER_SHA,'elf_machine':'AArch64',
      'elf_type':'DYN-PIE','dt_needed':member['needed'],'runpath':['$ORIGIN']},
      'new build did not reproduce original complete ELF identity')
    require(receipt.get('model') == generation['model'] and receipt.get('mmproj') == generation['mmproj'],
            'compile metadata model pins differ')
    expected_sdk = json.loads((app/'provenance/ui-venus-app-r1/sdk-runtime-pins.json').read_bytes())['files']
    require([{k:row[k] for k in ('name','bytes','sha256')} for row in receipt['sdk_libraries']] == expected_sdk,
            'new native build SDK closure differs')
    boundary_file = app/'provenance/ui-venus-app-r1/native-worker/SOURCE-BOUNDARY.json'
    require(sha(boundary_file) == pins['source_boundary_sha256'], 'frozen Q4_0 source boundary differs')
    boundary = json.loads(boundary_file.read_bytes())
    expected_boundary = {
      'schema':'hepta.ui-venus.app-q4_0-native-boundary.v1','passed':True,
      'baseline_source_generation_sha256':pins['baseline_app_source_generation_sha256'],
      'original_files':19,'original_files_unchanged':18,
      'original_files_changed':['native/venus-runtime.inc'],
      'only_model_identity_literals_changed':True,'changed_literal_count':4,
      'original_core_byte_unchanged':False,'worker_c_and_app_wrapper_bytes_unchanged':True,
      'same_directory_bootstrap_byte_unchanged':True,'entry_guard_bytes_unchanged':True,
      'phone_contact':False,'inference_run':False}
    for key,value in expected_boundary.items():
        require(type(boundary.get(key)) is type(value) and boundary[key] == value,
                'frozen Q4_0 source boundary contract differs: '+key)
    require([{k:row[k] for k in ('path','bytes','sha256')} for row in boundary['files']] == generation['files'],
            'Q4_0 boundary does not bind all 19 native source files')
    require(type(receipt.get('source_boundary')) is dict and
            json.dumps(receipt['source_boundary'],sort_keys=True,allow_nan=False) ==
            json.dumps(boundary,sort_keys=True,allow_nan=False),
            'new native build did not prove the exact 19/18/4 model-only source boundary')
    required_imports=['geniex_vlm_create','geniex_vlm_get_capabilities','geniex_vlm_apply_chat_template','geniex_vlm_generate','geniex_vlm_destroy']
    require(receipt.get('required_vlm_imports') == required_imports, 'actual VLM import qualification differs')
    require(receipt.get('sha2_instruction_owners') == {'hepta_sha256_armv8_blocks':56},
            'runtime SHA2 gate qualification differs')

def check_report(report, app):
    for key in ('source_build_completed','original_runtime_byte_identity','original_assembler_allowed',
                'worker_rebuilt','original_receipt_copied_unchanged'):
        require(report.get(key) is True, 'incomplete fresh UI-Venus rebuild: '+key)
    for key in ('phone_contacted','pins_modified','elf_rewritten','app_source_modified','android_execution_performed',
                'model_inference_performed','apk_assembled'):
        require(report.get(key) is False, 'unexpected rebuild effect: '+key)
    require(report.get('state') == 'exact_original_ui_venus_worker_rebuilt' and
            type(report.get('process_exit_code')) is int and report['process_exit_code'] == 0,
            'UI-Venus exact-byte rebuild did not complete')
    require(report.get('app_manifest_sha256') == APP_SHA and report.get('helper_sha256') == sha(Path(__file__)),
            'public source/helper differs')
    require(report.get('native_source_manifest_sha256') == NATIVE_MANIFEST_SHA and
            report.get('frozen_native_builder_sha256') == NATIVE_BUILDER_SHA and
            report.get('retained_original_build_receipt_sha256') == ORIGINAL_RECEIPT_SHA,
            'native build source/provenance differs')
    require(report.get('toolchain', {}).get('host_tag') == 'darwin-x86_64',
            'fresh native build must record the actual macOS toolchain')
    require(type(report.get('native_builder_exit_code')) is int and report['native_builder_exit_code'] == 0,
            'native builder did not exit successfully')
    fresh = report.get('native_build_receipt')
    require(type(fresh) is dict, 'actual new native receipt missing')
    require(hashlib.sha256((json.dumps(fresh,indent=2)+'\n').encode()).hexdigest() == report.get('native_build_receipt_sha256'),
            'embedded fresh native receipt bytes/hash differ')
    check_native_receipt(fresh, app, runtime_api(app).load_pins(app))

def write_json(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write('\n');stream.flush();os.fsync(stream.fileno())

def build(args):
    out=args.output.resolve()
    for source in (args.app_source,args.ndk,args.sdk_libs):
        source=source.resolve(strict=True)
        require(out != source and source not in out.parents,'new output must be outside original source/runtime/toolchain')
    out.mkdir(mode=0o700,parents=True,exist_ok=False)
    report={'schema':'hepta.ui-venus.fixed-source-rebuild.v1','helper_revision':'r2-code20-public-source',
      'app_manifest_sha256':APP_SHA,'helper_sha256':sha(Path(__file__)),
      'native_source_manifest_sha256':NATIVE_MANIFEST_SHA,'frozen_native_builder_sha256':NATIVE_BUILDER_SHA,
      'retained_original_build_receipt_sha256':ORIGINAL_RECEIPT_SHA,'state':'preflight',
      'source_build_completed':False,'original_runtime_byte_identity':False,'original_assembler_allowed':False,
      'worker_rebuilt':False,'original_receipt_copied_unchanged':False,'phone_contacted':False,
      'pins_modified':False,'elf_rewritten':False,'app_source_modified':False,'android_execution_performed':False,
      'model_inference_performed':False,'apk_assembled':False,'commands':[],'errors':[]}
    code=2
    try:
        require(platform.system() == 'Darwin','actual macOS source rebuild required')
        app=verify_frozen_source(args.app_source)
        _, transport=dependencies()
        compiler_bytes=transport.read(args.compiler_identity)
        compiler=transport.obj(compiler_bytes)
        ndk=args.ndk.resolve(strict=True)
        clang=ndk/'toolchains/llvm/prebuilt/darwin-x86_64/bin/clang'
        report['toolchain']={'host_tag':'darwin-x86_64','clang_sha256':sha(clang),
                             'ndk_revision_observed':'28.1.13356709',
                             'source_properties_sha256':sha(ndk/'source.properties')}
        transport.check_compiler(report,compiler)
        require(report['toolchain']['source_properties_sha256'] == SOURCE_PROPERTIES_SHA,
                'actual NDK properties differ')
        native=app/'provenance/ui-venus-app-r1/native-worker'
        require(sha(native/'DRAFT-MANIFEST.json')==NATIVE_MANIFEST_SHA and
                sha(native/'tools/build_android.py')==NATIVE_BUILDER_SHA,'native source or builder changed')
        api=runtime_api(app);pins=api.load_pins(app)
        original=app/'provenance/ui-venus-app-r1/NATIVE-BUILD-RECEIPT.json'
        require(sha(original)==ORIGINAL_RECEIPT_SHA,'historical native receipt changed')
        env=dict(os.environ)
        for key in REMOVED_ENV:env.pop(key,None)
        env['PYTHONDONTWRITEBYTECODE']='1'
        command=[sys.executable,'-B',str(native/'tools/build_android.py'),'--source',str(native),
                 '--ndk',str(ndk),'--sdk-libs',str(args.sdk_libs.resolve(strict=True)),
                 '--output',str(out/'native-build')]
        report['commands'].append({'stage':'fresh-native-compile-link-original-strip-recipe','argv':command})
        started=time.monotonic()
        with (out/'native-build.stdout').open('xb') as stdout,(out/'native-build.stderr').open('xb') as stderr:
            result=subprocess.run(command,env=env,stdout=stdout,stderr=stderr,timeout=240)
        report['native_builder_exit_code']=result.returncode
        report['native_build_elapsed_seconds']=time.monotonic()-started
        require(result.returncode == 0,'fresh native source compile failed; retained logs are authoritative')
        fresh_bytes=transport.read(out/'native-build/BUILD-RECEIPT.json',131072)
        fresh=transport.obj(fresh_bytes)
        report['native_build_receipt_sha256']=hashlib.sha256(fresh_bytes).hexdigest()
        report['native_build_receipt']=fresh
        report['source_build_completed']=True;report['worker_rebuilt']=True
        check_native_receipt(fresh,app,pins)
        worker=out/'native-build'/WORKER
        require(worker.stat().st_size==WORKER_BYTES and sha(worker)==WORKER_SHA,
                'fresh worker whole-file identity differs; original pins remain unchanged')
        verify_frozen_source(app)
        staged=out/'runtime-pending';staged.mkdir()
        shutil.copyfile(worker,staged/WORKER);shutil.copyfile(original,staged/'BUILD-RECEIPT.json')
        api.verify_ui_venus_runtime(app,staged)
        require({p.name for p in staged.iterdir()}=={WORKER,'BUILD-RECEIPT.json'},'unexpected runtime payload')
        staged.rename(out/'runtime')
        report.update(state='exact_original_ui_venus_worker_rebuilt',original_runtime_byte_identity=True,
                      original_assembler_allowed=True,original_receipt_copied_unchanged=True,process_exit_code=0)
        check_report(report,app);code=0
    except Exception as error:
        report.update(state='rejected',original_assembler_allowed=False,process_exit_code=3)
        report['errors'].append(type(error).__name__+': '+str(error));code=3
    finally:
        write_json(out/'NEW-BUILD-RECEIPT.json',report)
        print(json.dumps({key:report.get(key) for key in ('state','app_manifest_sha256','source_build_completed',
              'original_runtime_byte_identity','original_assembler_allowed','errors')}))
    return code

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app-source',type=Path,required=True)
    parser.add_argument('--ndk',type=Path,required=True)
    parser.add_argument('--sdk-libs',type=Path,required=True)
    parser.add_argument('--compiler-identity',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    return build(parser.parse_args())
if __name__=='__main__':
    sys.dont_write_bytecode=True
    raise SystemExit(main())
