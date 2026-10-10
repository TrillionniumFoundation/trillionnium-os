#!/usr/bin/env python3
"""Build the kernel-compatible owner-open EROFS candidate from exact staging.

Never mounts, installs, substitutes a filesystem, or claims Android/runtime
qualification. Two independent normalized copies must reproduce exact bytes.
"""
from pathlib import Path
import argparse, hashlib, json, os, re, shutil, struct, subprocess
import build_owner_open_rootfs_image_release as common

def digest(path):
    return common.sha256_path(path,common.MAX_IMAGE_BYTES)

def build(args):
    if not args.execute: raise common.ImageError('explicit --execute required')
    common.new_output(args.output)
    common.stable_file(args.mkfs,'mkfs.erofs',common.MAX_TOOL_BYTES,executable=True)
    tool_sha,_=digest(args.mkfs)
    if tool_sha!=args.expected_mkfs_sha256: raise common.ImageError('mkfs tool hash differs')
    manifest,raw,root,_=common.validate_staging(args.staging)
    args.output.mkdir(mode=0o700)
    fsconfig=args.output/'rootfs.fs-config'
    contexts=args.output/'rootfs.file-contexts'
    lines=['/ 0 0 0755 capabilities=0x0']
    context_lines=['/.* u:object_r:trillionnium_owner_open_payload_file:s0']
    for p in sorted(root.rglob('*')):
        relative=p.relative_to(root).as_posix()
        if p.is_symlink(): raise common.ImageError('staging cannot contain symlinks')
        mode=p.stat().st_mode&0o777
        lines.append(f'{relative} 0 0 {mode:04o} capabilities=0x0')
        if p.is_file() and mode&0o111:
            context_lines.append('/'+re.escape(relative)+' -- u:object_r:trillionnium_owner_open_payload_exec:s0')
    fsconfig.write_text('\n'.join(lines)+'\n');fsconfig.chmod(0o444)
    contexts.write_text('\n'.join(context_lines)+'\n');contexts.chmod(0o444)
    options=['-b4096','-C4096','-T0','-U','62803760-1008-4000-8000-000000000001','--fs-config-file',str(fsconfig),'--file-contexts',str(contexts),'-zlz4hc']
    runs=[]
    for n in range(2):
        normalized=args.output/f'normalized-{n}'
        common.normalize_copy(root,normalized)
        common.validate_root_snapshot(normalized,manifest,raw)
        image=args.output/f'run-{n}.erofs'
        result=subprocess.run([str(args.mkfs),*options,str(image),str(normalized)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=300,env={**os.environ,'SOURCE_DATE_EPOCH':'0'})
        (args.output/f'mkfs-{n}.stdout').write_bytes(result.stdout)
        (args.output/f'mkfs-{n}.stderr').write_bytes(result.stderr)
        if result.returncode: raise common.ImageError('real mkfs failed; see retained logs')
        common.validate_root_snapshot(normalized,manifest,raw)
        if digest(args.mkfs)[0]!=tool_sha: raise common.ImageError('tool changed')
        image.chmod(0o444)
        sha,size=digest(image)
        with image.open('rb') as stream:
            stream.seek(1024);superblock=stream.read(128)
        if struct.unpack_from('<I',superblock)[0]!=0xE0F5E1E2 or superblock[12]!=12:
            raise common.ImageError('actual image is not EROFS with 4K blocks')
        # LZ4 zero-padding incompat bit is required by this measured OEM kernel.
        if not struct.unpack_from('<I',superblock,80)[0]&1:
            raise common.ImageError('LZ4 zero-padding feature missing')
        runs.append({'returncode':result.returncode,'image_sha256':sha,'image_bytes':size,'stdout_sha256':hashlib.sha256(result.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(result.stderr).hexdigest()})
    if runs[0]['image_sha256']!=runs[1]['image_sha256']: raise common.ImageError('independent EROFS builds differ')
    common.validate_root_snapshot(root,manifest,raw)
    image=args.output/'owner-open-rootfs.erofs'
    shutil.copyfile(args.output/'run-0.erofs',image);image.chmod(0o444)
    value={
      'schema':'org.trillionnium.owner-open.rootfs-image-manifest.v1',
      'payload_id':manifest['payload_id'],'architecture':manifest['architecture'],'libc':manifest['libc'],
      'filesystem':'erofs','kernel_contract':'CONFIG_EROFS_FS=y; CONFIG_SQUASHFS=n; 4K; LZ4 zero-padding',
      'image_sha256':runs[0]['image_sha256'],'image_bytes':runs[0]['image_bytes'],
      'staging_manifest_sha256':hashlib.sha256(raw).hexdigest(),
      'entry_count':manifest['entry_count'],'entries':manifest['entries'],'runtime_state_directory':manifest['runtime_state_directory'],
      'mkfs_erofs':{'path':str(args.mkfs),'sha256':tool_sha,'options':options,'environment':{'SOURCE_DATE_EPOCH':'0'},'normalized_inode_epoch':0,'filesystem_epoch':0,'fs_config_sha256':digest(fsconfig)[0],'file_contexts_sha256':digest(contexts)[0]},
      'reproducible':True,'reproducibility_runs':2,'build_runs':runs,
      'claims':{'staging_revalidated':True,'deterministic_options_observed':True,'independent_builds_byte_identical':True,'rootfs_image_built':True,'android_module_bound':False,'target_files_built':False,'image_included':False,'physical_device_observed':False,'public_release':False},
      'claim_ceiling':'ROOTFS_IMAGE_BUILT_NOT_ANDROID_INCLUDED'
    }
    common.atomic_json(args.output/'owner-open-rootfs.image-manifest.json',value,0o600)
    (args.output/'owner-open-rootfs.image-manifest.json').chmod(0o444)
    (args.output/'owner-open-rootfs.erofs.sha256').write_text(value['image_sha256']+'\n')
    (args.output/'owner-open-rootfs.erofs.sha256').chmod(0o444)
    return {'output':str(args.output),'image_sha256':value['image_sha256'],'image_bytes':value['image_bytes'],'entries':value['entry_count'],'filesystem':'erofs','claims':value['claims']}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--execute',action='store_true');p.add_argument('--staging',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--mkfs',type=Path,required=True);p.add_argument('--expected-mkfs-sha256',required=True)
    try: print(json.dumps(build(p.parse_args()),sort_keys=True))
    except (common.ImageError,OSError,ValueError,subprocess.SubprocessError) as e: p.exit(1,f'HOLD: {e}\n')
