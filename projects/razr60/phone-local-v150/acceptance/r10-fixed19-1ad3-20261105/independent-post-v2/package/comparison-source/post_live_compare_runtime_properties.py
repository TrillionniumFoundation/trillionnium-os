#!/usr/bin/env python3
"""Complete independent comparison of the actual runtime-property live-policy export.

No policy activation, phone transport, or opaque-rule fallbacks. The production
table readers and SETools package are the existing exact pinned host tools.
"""
import argparse
from collections import Counter
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import types

WORKER='trillionnium_owner_open_phone_worker'
ALLOCATOR='hal_graphics_allocator_default'
PARENT_SHA='50f07eccca1a1afd59fac1c31f4d40a26e5396635c6516e695694a8923fd3ea7'
PARENT_BYTES=2667608
ROOT_DECISION_SHA='5a08041da77eeec9168c869ae76adae0a117a5e34872aa07a1a096bc06a36132'
ROOT_DECISION_BYTES=24830
ROOT_DECISION_STATE='FORTY_FOUR_ATOM_HOST_CANDIDATE_SELECTED_LIVE_APPLY_PENDING_SOURCE_REVIEW'
PARENT_ADOPTION_SHA='a5f94e24ead8b7b811025197439ddbfa762d05eaf7d1de2a5f61f26d9502ebd5'
RULE_SHA='fa32d9ae9dfd1f8e9100ebb966a327bf059ed53d307b58be9ed69c8c9b90c1d6'
FULL_RULE_SHA='424e1c680d37583f039c8cc5e2727200b3f9ad8fd29d35616173a5102b0218d1'
PARENT_RULE_SHA='aeda92123f1d043de2c53dd345dd7372b98da7b776299d57bda531dda868e4a1'
IMAGE_SOURCE_SHA='da60ee90209a26216f053064a7ca47ebcb73c4730b4e00378886b5d653de09aa'
BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
APPROVED_ATOMS=(('allow', 'trillionnium_owner_open_phone_worker', 'build_attestation_prop', 'file', 'getattr'), ('allow', 'trillionnium_owner_open_phone_worker', 'build_attestation_prop', 'file', 'open'), ('allow', 'trillionnium_owner_open_phone_worker', 'build_attestation_prop', 'file', 'read'), ('allow', 'trillionnium_owner_open_phone_worker', 'build_attestation_prop', 'file', 'map'), ('allow', 'trillionnium_owner_open_phone_worker', 'dalvik_config_prop', 'file', 'getattr'), ('allow', 'trillionnium_owner_open_phone_worker', 'dalvik_config_prop', 'file', 'open'), ('allow', 'trillionnium_owner_open_phone_worker', 'dalvik_config_prop', 'file', 'read'), ('allow', 'trillionnium_owner_open_phone_worker', 'dalvik_config_prop', 'file', 'map'), ('allow', 'trillionnium_owner_open_phone_worker', 'dalvik_dynamic_config_prop', 'file', 'getattr'), ('allow', 'trillionnium_owner_open_phone_worker', 'dalvik_dynamic_config_prop', 'file', 'open'), ('allow', 'trillionnium_owner_open_phone_worker', 'dalvik_dynamic_config_prop', 'file', 'read'), ('allow', 'trillionnium_owner_open_phone_worker', 'dalvik_dynamic_config_prop', 'file', 'map'), ('allow', 'trillionnium_owner_open_phone_worker', 'dalvik_runtime_prop', 'file', 'getattr'), ('allow', 'trillionnium_owner_open_phone_worker', 'dalvik_runtime_prop', 'file', 'open'), ('allow', 'trillionnium_owner_open_phone_worker', 'dalvik_runtime_prop', 'file', 'read'), ('allow', 'trillionnium_owner_open_phone_worker', 'dalvik_runtime_prop', 'file', 'map'), ('allow', 'trillionnium_owner_open_phone_worker', 'default_prop', 'file', 'getattr'), ('allow', 'trillionnium_owner_open_phone_worker', 'default_prop', 'file', 'open'), ('allow', 'trillionnium_owner_open_phone_worker', 'default_prop', 'file', 'read'), ('allow', 'trillionnium_owner_open_phone_worker', 'default_prop', 'file', 'map'), ('allow', 'trillionnium_owner_open_phone_worker', 'odsign_prop', 'file', 'getattr'), ('allow', 'trillionnium_owner_open_phone_worker', 'odsign_prop', 'file', 'open'), ('allow', 'trillionnium_owner_open_phone_worker', 'odsign_prop', 'file', 'read'), ('allow', 'trillionnium_owner_open_phone_worker', 'odsign_prop', 'file', 'map'), ('allow', 'trillionnium_owner_open_phone_worker', 'persist_debug_prop', 'file', 'getattr'), ('allow', 'trillionnium_owner_open_phone_worker', 'persist_debug_prop', 'file', 'open'), ('allow', 'trillionnium_owner_open_phone_worker', 'persist_debug_prop', 'file', 'read'), ('allow', 'trillionnium_owner_open_phone_worker', 'persist_debug_prop', 'file', 'map'), ('allow', 'trillionnium_owner_open_phone_worker', 'qemu_sf_lcd_density_prop', 'file', 'getattr'), ('allow', 'trillionnium_owner_open_phone_worker', 'qemu_sf_lcd_density_prop', 'file', 'open'), ('allow', 'trillionnium_owner_open_phone_worker', 'qemu_sf_lcd_density_prop', 'file', 'read'), ('allow', 'trillionnium_owner_open_phone_worker', 'qemu_sf_lcd_density_prop', 'file', 'map'), ('allow', 'trillionnium_owner_open_phone_worker', 'radio_prop', 'file', 'getattr'), ('allow', 'trillionnium_owner_open_phone_worker', 'radio_prop', 'file', 'open'), ('allow', 'trillionnium_owner_open_phone_worker', 'radio_prop', 'file', 'read'), ('allow', 'trillionnium_owner_open_phone_worker', 'radio_prop', 'file', 'map'), ('allow', 'trillionnium_owner_open_phone_worker', 'system_prop', 'file', 'getattr'), ('allow', 'trillionnium_owner_open_phone_worker', 'system_prop', 'file', 'open'), ('allow', 'trillionnium_owner_open_phone_worker', 'system_prop', 'file', 'read'), ('allow', 'trillionnium_owner_open_phone_worker', 'system_prop', 'file', 'map'), ('allow', 'trillionnium_owner_open_phone_worker', 'vendor_mot_hw_prop', 'file', 'getattr'), ('allow', 'trillionnium_owner_open_phone_worker', 'vendor_mot_hw_prop', 'file', 'open'), ('allow', 'trillionnium_owner_open_phone_worker', 'vendor_mot_hw_prop', 'file', 'read'), ('allow', 'trillionnium_owner_open_phone_worker', 'vendor_mot_hw_prop', 'file', 'map'))
APPROVED_ROWS=(('trillionnium_owner_open_phone_worker', 'build_attestation_prop', 'file', ('getattr', 'open', 'read', 'map')), ('trillionnium_owner_open_phone_worker', 'dalvik_config_prop', 'file', ('getattr', 'open', 'read', 'map')), ('trillionnium_owner_open_phone_worker', 'dalvik_dynamic_config_prop', 'file', ('getattr', 'open', 'read', 'map')), ('trillionnium_owner_open_phone_worker', 'dalvik_runtime_prop', 'file', ('getattr', 'open', 'read', 'map')), ('trillionnium_owner_open_phone_worker', 'default_prop', 'file', ('getattr', 'open', 'read', 'map')), ('trillionnium_owner_open_phone_worker', 'odsign_prop', 'file', ('getattr', 'open', 'read', 'map')), ('trillionnium_owner_open_phone_worker', 'persist_debug_prop', 'file', ('getattr', 'open', 'read', 'map')), ('trillionnium_owner_open_phone_worker', 'qemu_sf_lcd_density_prop', 'file', ('getattr', 'open', 'read', 'map')), ('trillionnium_owner_open_phone_worker', 'radio_prop', 'file', ('getattr', 'open', 'read', 'map')), ('trillionnium_owner_open_phone_worker', 'system_prop', 'file', ('getattr', 'open', 'read', 'map')), ('trillionnium_owner_open_phone_worker', 'vendor_mot_hw_prop', 'file', ('getattr', 'open', 'read', 'map')))
PARENT_AV_PINS=('5d3c1bc4ef9f799880c530700d7db6065d3c5b3772fbc2b18e02f8940d4f3baf', '8998d0d4797cbc42e3fa6ed347d11ec3bc68c148de7e80300cf0da01bbc13fcd', 'b56b37b7cdc39a5b9f12751ada3e379d896365e764502e987fa3a917c2561cc5', 'd405f388bdcfd78ecbf9c46e14a1d53f93423d74eb3f069bacc58169a6969a8c', 'db3c8b1addf98f370229cc71c37d6bbe09cc67c6c187e13f83d4d46b638c825a', '433c5cd49c3d8e8f2183ed230c30f3064cc408ea8fb21a9a3bb43f744320b4ee', '310ee62c1747b6d8e9870f2d397dde04fbe6ddd0f5a4e4cb44b1716d3b34507a', 'c08fa538cc91dc8ed0a15e1550d478694a5269cbc359155971f83f3f847d44d6', 'b63d9c430d0ad3c92b60fccc9d0d14d131fb209daf7ece0e434458122901bf0a', '9ccb9cd491adbdef4e7a32b4ea39744f42081bd829edd03cd689e452cb844593', '7c1be139ba444d9919ce6d3112e50ad788a9121c8721e2adad7d9c57d8b08c3e')
PARENT_SET_AV_PINS=('7ebd6a8d40ef761f98523dea81c9baddecbf6dedea67b831d6627e02d0b6b2da', '296344c44ebbeb2146cc37cab349efdd5de2e8b7577f16cb12292d35cd94f857', '0c0386666b5bd476b93477564be40a520bb4f4d8093bce976780e6ad8a6d932d', 'a689fe2461b430b65a2d47ff0938c9801bea7e6619198091e7ee08b0a58bd955', '99176f65e11969ba1086eddd5136e5c8e5c1bfcf916ecb79f126a1499292e90a', 'bcfd498d482c8a526f71387d5e57f99d08ceaf26cfa67c5a935e63383c64ee3a', 'ccf3e962eb52e488217d30b2b7a09a3d2ded0d482aa8a16f6ea2636d54dd42a2', '319e5dfc5058e7e0d5a4a3577c5679c00ef80fde180c79e16b59f684834168ad', '1a767a6edf976157d715450cb2853e4e882208aca338c320ee6c7ab43e954375', 'a36424018985d2936bfa3d9564d146a1431a4d95980e3ba3affd4f1b25595c28', '964b5b8a36e2eab91df989af00bb669c984ec77c5fcb75b27cfce7e83ecdbaf9')
UNCONDITIONAL=('unconditional',)
STANDARD_AV={'allow','auditallow','dontaudit','neverallow'}
EXTENDED_AV={'allowxperm','auditallowxperm','dontauditxperm','neverallowxperm'}
TYPE_RULES={'type_transition','type_change','type_member'}
NON_TE_TABLES=('categories','commons','classes','constraints','defaults','bounds',
    'ibendportcons','ibpkeycons','levels','mlsrules','netifcons','nodecons','polcaps',
    'portcons','rbacrules','sensitivities')

def need(ok,message):
    if not ok:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def encode(value):return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()
def strict(raw):
    def pairs(rows):
        value={}
        for key,item in rows:
            need(key not in value,'duplicate JSON key');value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
def metadata(s):return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))

class Originals:
    def __init__(self):self.seen={}
    def read(self,path,expected=None,size=None,limit=64*1024*1024):
        path=Path(path);need(path.is_absolute() and path.resolve(strict=True)==path,'canonical original path')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<=a.st_size<=limit,'bounded regular original')
            with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(limit+1)
            need(metadata(a)==metadata(os.fstat(fd))==metadata(path.lstat()) and len(raw)==a.st_size,'original changed during read')
        finally:os.close(fd)
        need(expected is None or sha(raw)==expected,'original hash differs: '+str(path))
        need(size is None or len(raw)==size,'original size differs: '+str(path))
        row=(metadata(a),sha(raw));need(path not in self.seen or self.seen[path]==row,'original changed between reads')
        self.seen[path]=row;return raw
    def descriptor(self,row):
        need(isinstance(row,dict) and set(row)=={'path','bytes','sha256'} and type(row['bytes']) is int and row['bytes']>=0 and re.fullmatch('[0-9a-f]{64}',row['sha256']),'exact original descriptor')
        return self.read(row['path'],row['sha256'],row['bytes'])
    def recheck(self):
        for path,(meta,pin) in list(self.seen.items()):self.read(path,pin,meta[6])

def unique_dictionary(rows,label):
    result={}
    for key,value in rows:
        need(key not in result,'duplicate '+label+' symbol');result[key]=value
    return result

def conditional_expression(conditional,bools,operator_type):
    out=[];stack=0
    for token in conditional.expression():
        if isinstance(token,operator_type):
            op=str(token);arity=1 if token.unary is True else 2
            need(op in {'!','&&','||','^','==','!='} and type(token.unary) is bool,'unknown conditional operator')
            need(stack>=arity,'malformed conditional RPN');stack-=arity-1
            out.append(('operator',op,arity))
        else:
            name=str(token);need(name in bools,'conditional token is not a declared Boolean')
            out.append(('boolean',name));stack+=1
    need(out and stack==1,'complete conditional expression')
    need(sorted(str(x) for x in conditional.booleans)==sorted({t[1] for t in out if t[0]=='boolean'}),'conditional Boolean association')
    return tuple(out)

def rule_atoms(rule,bools,api,*,forced_conditional=None):
    kind=str(rule.ruletype)
    need(kind in STANDARD_AV|EXTENDED_AV|TYPE_RULES,'unsupported TE rule kind: '+kind)
    if forced_conditional is None:
        try:
            conditional=rule.conditional
        except api.exception.RuleNotConditional:
            cond=UNCONDITIONAL
        else:
            branch=rule.conditional_block;need(type(branch) is bool,'explicit conditional branch required')
            cond=('conditional',conditional_expression(conditional,bools,api.policyrep.ConditionalOperator),'true' if branch else 'false')
    else:
        cond=forced_conditional
        actual=rule_atoms(rule,bools,api)
        need(all(a[4]==cond for a in actual),'conditional table/rule identity differs')
        return actual
    head=(kind,str(rule.source),str(rule.target),str(rule.tclass),cond)
    need(all(head[i] for i in range(4)),'empty TE identity')
    if kind in STANDARD_AV:
        need(rule.extended is False,'standard AV marked extended')
        perms=sorted(str(p) for p in rule.perms);need(perms and len(perms)==len(set(perms)),'standard AV permission set')
        return [head+('permission',p) for p in perms]
    if kind in EXTENDED_AV:
        need(rule.extended is True,'xperm rule lacks explicit extended flag')
        xtype=str(rule.xperm_type);need(xtype in {'ioctl','nlmsg'},'unsupported explicit xperm type')
        perms=sorted(rule.perms);need(perms and len(perms)==len(set(perms)) and all(type(p) is int and 0<=p<=65535 for p in perms),'explicit full xperm integer set')
        return [head+('xperm',xtype,p) for p in perms]
    need(rule.extended is False,'type rule marked extended')
    filename=''
    if kind=='type_transition':
        try:filename=rule.filename
        except api.exception.TERuleNoFilename:filename=''
        need(isinstance(filename,str),'type transition filename')
    return [head+('default',str(rule.default),'filename',filename)]

def policy_snapshot(policy,api):
    bools=unique_dictionary(((str(b),b.state) for b in policy.bools()),'Boolean')
    need(all(type(v) is bool for v in bools.values()),'Boolean state type')
    types=unique_dictionary(((str(t),{'attributes':sorted(str(a) for a in t.attributes()),'aliases':sorted(str(a) for a in t.aliases()),'permissive':t.ispermissive}) for t in policy.types()),'type')
    attrs=unique_dictionary(((str(a),sorted(str(t) for t in a.expand())) for a in policy.typeattributes()),'type attribute')
    classes={}
    for c in policy.classes():
        try:common=str(c.common)
        except api.exception.NoCommon:common=None
        name=str(c);need(name not in classes,'duplicate class')
        classes[name]={'own_permissions':sorted(str(p) for p in c.perms),'common':common,'statement':c.statement()}
    commons=unique_dictionary(((str(c),{'permissions':sorted(str(p) for p in c.perms),'statement':c.statement()}) for c in policy.commons()),'common')
    atoms=Counter();kinds=Counter();raw_rules=0;conditional_atoms=Counter()
    for rule in policy.terules():
        raw_rules+=1;need(raw_rules<=2000000,'bounded complete TE inventory')
        kinds[str(rule.ruletype)]+=1
        aa=rule_atoms(rule,bools,api);atoms.update(aa)
        conditional_atoms.update(a for a in aa if a[4]!=UNCONDITIONAL)
    conditionals=[];table_conditional=Counter()
    for c in policy.conditionals():
        expression=conditional_expression(c,bools,api.policyrep.ConditionalOperator)
        row={'expression':expression,'true_atoms':[],'false_atoms':[]}
        for branch,method in (('true',c.true_rules),('false',c.false_rules)):
            part=Counter()
            for r in method():part.update(rule_atoms(r,bools,api,forced_conditional=('conditional',expression,branch)))
            row[branch+'_atoms']=sorted(part.items());table_conditional.update(part)
        conditionals.append(row)
    need(table_conditional==conditional_atoms,'all conditional rules retain exact expression and branch association')
    tables={}
    for name in NON_TE_TABLES:
        values=[]
        for value in getattr(policy,name)():
            text=value.statement() if hasattr(value,'statement') else str(value)
            need(isinstance(text,str),'symbolic table representation');values.append(text)
        tables[name]=sorted(values)  # multiplicity retained; no string-keyed dict
    return {'metadata':{k:str(getattr(policy,k)) for k in ('version','mls','handle_unknown','target_platform')},
        'types':types,'type_attributes':attrs,'booleans':bools,'classes_with_common':classes,
        'common_permissions':commons,'conditionals':sorted(conditionals,key=canonical),
        'symbolic_tables':tables,'te_atoms':atoms,'te_raw_rule_count':raw_rules,'te_kind_counts':dict(kinds)}

def atom_digest(counter):
    h=hashlib.sha256()
    for atom,count in sorted(counter.items()):h.update(canonical([atom,count])+b'\n')
    return h.hexdigest()
def snapshot_summary(s):
    summary={}
    for name,value in s.items():
        if name=='te_atoms':summary[name]={'distinct_atoms':len(value),'atoms_with_multiplicity':sum(value.values()),'sha256':atom_digest(value)}
        else:summary[name]={'sha256':sha(canonical(value)),'count':len(value) if isinstance(value,(dict,list)) else value}
    return summary
def same_snapshot(a,b):
    return all(a[k]==b[k] for k in a)

def materialize_isolated_package(reader,source_package,inventory,out):
    # Only the 81 reviewed source/extension originals become importable. The
    # original installation and all its extra entries remain untouched and
    # are never placed on sys.path by this execution.
    original_root=source_package/'setools'
    original_rows=inventory['package_files']
    need(len(original_rows)==81 and len({r['path'] for r in original_rows})==81,'exact source inventory')
    for row in original_rows:
        need(Path(row['path']).is_relative_to(original_root),'fixed original package subtree')
        reader.descriptor(row)
    need(out.parent.resolve(strict=True)==out.parent and not out.exists() and not out.is_symlink(),'new private audit root')
    def sync(directory):
        fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
    def mkdir(directory):
        need(directory.parent.resolve(strict=True)==directory.parent,'private import parent canonical')
        directory.mkdir(mode=0o700);sync(directory.parent)
    mkdir(out);package=out/'owned-import-package';mkdir(package)
    relatives=[Path(row['path']).relative_to(source_package) for row in original_rows]
    directories={Path('setools')}
    for rel in relatives:
        directories.update(p for p in rel.parents if p!=Path('.'))
    for rel in sorted(directories,key=lambda x:(len(x.parts),str(x))):mkdir(package/rel)
    copied=[];mapping=[]
    for original,relative in zip(original_rows,relatives):
        raw=reader.descriptor(original);path=package/relative
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
        sync(path.parent)
        retained={'path':str(path),'bytes':len(raw),'sha256':sha(raw)}
        reader.descriptor(retained);copied.append(retained);mapping.append({'original':original,'retained':retained})
    reader.recheck()
    isolated_inventory={'package_files':copied}
    tree=verify_closed_package_tree(reader,package,isolated_inventory)
    return package,isolated_inventory,mapping,tree

def verify_closed_package_tree(reader,package,inventory):
    root=package/'setools'
    expected={Path(row['path']):row for row in inventory['package_files']}
    need(len(expected)==81 and all(path.is_relative_to(root) for path in expected),'exact fixed package subtree')
    directories={root}
    for path in expected:
        current=path.parent
        while current!=root:
            need(current.is_relative_to(root),'package path escaped root');directories.add(current);current=current.parent
    need(root/'__init__.py' in expected,'regular package initializer must be pinned')
    parent_aliases=sorted(n for n in os.listdir(package) if n=='setools' or n.startswith('setools.'))
    need(parent_aliases==['setools'],'unindexed same-name package/module/extension entry')
    seen={}
    for directory in sorted(directories):
        st=directory.lstat();need(stat.S_ISDIR(st.st_mode) and directory.resolve(strict=True)==directory,'canonical package directory')
        names=sorted(os.listdir(directory))
        wanted=sorted([path.name for path in expected if path.parent==directory]
                     +[path.name for path in directories if path!=root and path.parent==directory])
        need(names==wanted,'unindexed/missing importable package tree entry: '+str(directory))
        seen[str(directory)]={'metadata':list(metadata(st)),'names':names}
    for path,row in expected.items():reader.descriptor(row)
    for directory in directories:
        row=seen[str(directory)]
        need(list(metadata(directory.lstat()))==row['metadata'] and sorted(os.listdir(directory))==row['names'],
             'package tree changed during complete inventory')
    need(sorted(n for n in os.listdir(package) if n=='setools' or n.startswith('setools.'))==parent_aliases,
         'same-name package inputs changed')
    return {'package_root':str(root),'file_count':81,'directories':seen,'parent_aliases':parent_aliases}

def verify_loaded_package(reader,inventory):
    expected={row['path']:row for row in inventory['package_files']};loaded=[]
    for name,module in sorted(sys.modules.items()):
        if name!='setools' and not name.startswith('setools.'):continue
        path=getattr(module,'__file__',None)
        need(isinstance(path,str) and path in expected,'loaded package module is not an indexed source/extension')
        reader.descriptor(expected[path])
        paths=getattr(module,'__path__',None)
        if paths is not None:
            need(Path(path).name=='__init__.py' and list(paths)==[str(Path(path).parent)],
                 'unindexed package namespace/search path')
        loaded.append({'module':name,'original':expected[path],'package_paths':list(paths) if paths is not None else None})
    need(any(row['module']=='setools' for row in loaded),'actual package missing')
    return loaded

def require_reviewed_scope():
    pins=(ROOT_DECISION_SHA,RULE_SHA,FULL_RULE_SHA,IMAGE_SOURCE_SHA)
    need(all(isinstance(x,str) and re.fullmatch('[0-9a-f]{64}',x) for x in pins),
         'reviewed exact runtime-property scope and paired sources remain unpublished')
    need(type(ROOT_DECISION_BYTES) is int and ROOT_DECISION_BYTES>0 and isinstance(ROOT_DECISION_STATE,str)
         and ROOT_DECISION_STATE.endswith('_HOST_CANDIDATE_SELECTED_LIVE_APPLY_PENDING_SOURCE_REVIEW'),
         'reviewed Root decision original is absent')
    need(type(APPROVED_ROWS) is tuple and len(APPROVED_ROWS)>0 and type(APPROVED_ATOMS) is tuple,
         'reviewed exact property rows remain unpublished')
    targets=[]
    for row in APPROVED_ROWS:
        need(type(row) is tuple and len(row)==4 and row[0]==WORKER and row[2]=='file'
             and row[3]==('getattr','open','read','map')
             and isinstance(row[1],str) and re.fullmatch('[a-zA-Z0-9_]+',row[1]),
             'reviewed row is not the exact four read-only property permissions')
        targets.append(row[1])
    need(targets==sorted(set(targets)),'reviewed concrete targets must be unique and ordered')
    expected=tuple(('allow',src,target,cl,p) for src,target,cl,perms in APPROVED_ROWS for p in perms)
    need(APPROVED_ATOMS==expected and len(APPROVED_ATOMS)==len(set(APPROVED_ATOMS))==4*len(APPROVED_ROWS),
         'reviewed exact atom literal differs from row literal')
    for pins in (PARENT_AV_PINS,PARENT_SET_AV_PINS):
        need(type(pins) is tuple and len(pins)==len(APPROVED_ROWS)
             and all(isinstance(x,str) and re.fullmatch('[0-9a-f]{64}',x) for x in pins),
             'reviewed original read/set AV pins remain unpublished')

def validate_decision_and_rules(reader,plan):
    require_reviewed_scope()
    raw=reader.descriptor(plan['root_scope_decision'])
    need(sha(raw)==ROOT_DECISION_SHA and len(raw)==ROOT_DECISION_BYTES,'exact Root runtime-property scope decision')
    decision=strict(raw)
    need(decision['schema']=='hepta.root.runtime-properties.policy-scope-decision.v1'
         and decision['state']==ROOT_DECISION_STATE,'actual Root decision state')
    actual=tuple(('allow',r['source'],r['target'],r['class'],p) for r in decision['rows'] for p in r['permissions'])
    need(actual==APPROVED_ATOMS and len(actual)==len(set(actual))==decision['permission_atom_count'],
         'decision must approve exactly the separately reviewed literal atoms')
    need(decision['parent_policy']['sha256']==PARENT_SHA and decision['parent_policy']['bytes']==PARENT_BYTES
         and decision['existing_native5_twelve_atoms_retained'] is True and decision['live_policy_writes']==0
         and decision['native_qualification'] is False,'Root decision actual parent or effect scope differs')
    adoption_raw=reader.descriptor(plan['parent_adoption'])
    need(sha(adoption_raw)==PARENT_ADOPTION_SHA and len(adoption_raw)==146368
         and decision['parent_adoption_history']['sha256']==PARENT_ADOPTION_SHA,
         'actual adopted Native5 history must remain exact')
    adopted=strict(adoption_raw)
    need(adopted['schema']=='hepta.native5-r10.policy-adoption.v1'
         and adopted['actual_export']['bytes']==PARENT_BYTES and adopted['actual_export']['sha256']==PARENT_SHA
         and adopted['root_decision']['decision']=='ADOPT_INDEPENDENTLY_VERIFIED_ACTUAL_EXPORTED_POLICY'
         and adopted['root_decision']['actual_policy_sha256']==PARENT_SHA,
         'immutable parent adoption does not identify this exact actual policy')
    delta=reader.descriptor(plan['delta_rule']);full=reader.descriptor(plan['full_rule']);oldrule=reader.descriptor(plan['parent_rule'])
    wanted=b''.join((' '.join(a)+'\n').encode() for a in APPROVED_ATOMS)
    need(delta==wanted and sha(delta)==RULE_SHA and sha(full)==FULL_RULE_SHA and sha(oldrule)==PARENT_RULE_SHA,
         'exact reviewed read-only property delta and rule files')
    need(oldrule.endswith(b'\n') and full==oldrule+delta,'all existing rules including old twelve atoms must precede the exact append')
    return decision

def validate_live_records(reader,plan):
    # The plan names the independently reviewed host verifier explicitly.
    # Its own raw identity is distinct from the immutable verifier that the
    # phone actually executed. Both originals are mapped and checked below;
    # this source never embeds a future independent-verifier hash.
    mappings=plan['input_original_map']
    need(type(mappings) is list and 1<=len(mappings)<=512,'bounded explicit cross-host input map')
    index={};retained_total=0
    def key(row):
        need(type(row) is dict and set(row)=={'path','bytes','sha256'} and isinstance(row['path'],str)
             and Path(row['path']).is_absolute() and '..' not in Path(row['path']).parts
             and type(row['bytes']) is int and 0<=row['bytes']<=64*1024*1024
             and isinstance(row['sha256'],str) and re.fullmatch('[0-9a-f]{64}',row['sha256']),
             'exact cross-host original descriptor')
        return (row['path'],row['bytes'],row['sha256'])
    original_paths=set()
    for item in mappings:
        need(type(item) is dict and set(item)=={'original','retained'},'explicit original/retained pair')
        original=item['original'];retained=item['retained'];identity=key(original);key(retained)
        need(original['path'] not in original_paths and identity not in index,'duplicate original alias')
        need(all(original[k]==retained[k] for k in ('bytes','sha256')),'cross-host copy changed original bytes')
        original_paths.add(original['path']);index[identity]=retained;retained_total+=retained['bytes']
        need(retained_total<=128*1024*1024,'bounded retained provenance input total')
        reader.descriptor(retained)
    used=set()
    def get(original):
        identity=key(original);need(identity in index,'missing explicit retained original mapping')
        used.add(identity);return reader.descriptor(index[identity])
    live_raw=reader.descriptor(plan['live_provenance_inputs']);live=strict(live_raw)
    verifier_raw=reader.descriptor(plan['live_verifier_source'])
    applied_raw=reader.descriptor(plan['applied_verifier_source'])
    need(0<len(verifier_raw)<=262144,'bounded independent host verifier source')
    need(len(applied_raw)==124306 and sha(applied_raw)=='5cd18af19e1cd4cbe98542996fa41960bc36f697c6687ce201312b8ceda91c00',
         'exact immutable verifier executed by the original phone transaction')
    namespace={'__name__':'reviewed_runtime_properties_live_verifier','__file__':plan['live_verifier_source']['path'],
               '__reviewed_source_sha256__':sha(verifier_raw)}
    exec(compile(verifier_raw,plan['live_verifier_source']['path'],'exec'),namespace)
    summary=namespace['verify_live_capture'](live,read_pinned=get)
    need(summary['comparison_route']=='verified_semantic_export' and summary['expected_live_export'] is None
         and summary['policy_adoption_authorized'] is False and summary['phone_calls']==0,
         'post comparator cannot adopt policy or accept another provenance route')
    pairs=(('parent','parent'),('candidate','candidate'),('root_scope_decision','root_scope_decision'),
           ('parent_adoption_history','parent_adoption'))
    for original_name,local_name in pairs:
        original=summary[original_name];get(original)
        need(index[key(original)]==plan[local_name],'actual original identity is not the explicit parser input copy')
    need(live['schema']=='hepta.runtime-properties-r10.live-provenance-inputs.v2','explicit dual-identity live provenance')
    verifier_original=live['independent_verifier_source'];get(verifier_original)
    applied_original=live['originals']['policy_runtime_properties_verifier.original.py'];get(applied_original)
    need(summary['independent_verifier_source']==verifier_original
         and summary['applied_verifier_source']==applied_original
         and index[key(verifier_original)]==plan['live_verifier_source']
         and index[key(applied_original)]==plan['applied_verifier_source']
         and verifier_original['sha256']!=applied_original['sha256']
         and summary['binding']['verifier_source']=={'bytes':len(applied_raw),'sha256':sha(applied_raw)},
         'independent host verifier and actual applied verifier identities must remain distinct')
    need(sha(summary['original_files']['ROOT-SCOPE-DECISION.original.json'])==ROOT_DECISION_SHA
         and sha(summary['original_files']['live-policy-before.bin'])==PARENT_SHA
         and sha(summary['original_files']['live-policy-after.bin'])==plan['candidate']['sha256'],
         'live source originals do not match approved parent and actual export')
    build=strict(reader.descriptor(plan['image_build_result']))
    need(build['returncode']==0 and build['source']==plan['image_comparator_source']
         and build['binary']==plan['image_comparator'],'actual reviewed image binary build linkage')
    for stream in ('stdout','stderr'):need(reader.descriptor(build[stream])==b'','compiler original stream differs')
    for row in [build['compiler'],build['static_library'],build['runtime_library'],*build['installed_headers']]:reader.descriptor(row)
    need(build['static_library']['sha256']=='2174eb5cfde7050e7c82e7805675a45c62cc54e27547ea62517b3e4d2e96400b'
         and build['runtime_library']['sha256']=='c1e965eaae791bc4abc1fc2336a5433d7c483e5117778dbd06234b3fa9172092',
         'original installed image library identity')
    reader.recheck()
    return {'schema':'hepta.runtime-properties.post-live-originals-recheck.v2',
        'live_provenance_inputs':plan['live_provenance_inputs'],'live_provenance_raw_sha256':sha(live_raw),
        'input_original_map':mappings,'used_original_descriptors':[{'path':p,'bytes':n,'sha256':h} for p,n,h in sorted(used)],
        'live_provenance_verifier':plan['live_verifier_source'],
        'independent_verifier_source':plan['live_verifier_source'],'applied_verifier_source':plan['applied_verifier_source'],
        'independent_reviewed_verifier_source_executed':True,'actual_applied_verifier_source_preserved':True,
        'actual_original_parent':summary['parent'],'actual_original_candidate':summary['candidate'],
        'binding_sha256':summary['binding_sha256'],'host_capture_sha256':summary['host_capture_sha256'],
        'provenance_inputs_canonical_sha256':summary['provenance_inputs_sha256'],
        'root_transaction':summary['root_transaction'],'image_build_result':plan['image_build_result'],
        'phone_operations':0,'active_policy_writes':0,'policy_adoption_authorized':False}

def validate_parent_av(reader,plan):
    need(type(plan['parent_av_originals']) is list and len(plan['parent_av_originals'])==len(APPROVED_ROWS),
         'one fixed original parent read AV per reviewed type')
    result=[]
    for index,(src,target,cl,perms) in enumerate(APPROVED_ROWS):
        desc=plan['parent_av_originals'][index];raw=reader.descriptor(desc)
        need(sha(raw)==PARENT_AV_PINS[index],'exact previously executed parent read AV original')
        row=strict(raw)
        need(row['schema']=='hepta.offline-policy-av.v1' and row['state']=='COMPLETE_OFFLINE_AV_QUERY'
             and row['policy']['sha256']==PARENT_SHA and row['policy']['bytes']==PARENT_BYTES
             and row['policy']['input_unchanged'] is True
             and row['query']['source']=='u:r:'+src+':s0' and row['query']['target']=='u:object_r:'+target+':s0'
             and row['query']['class']==cl and row['query']['source_policy_permissive'] is False
             and row['query']['source_policy_neveraudit'] is False,'parent read AV context or original policy differs')
        need([p['name'] for p in row['permissions']]==list(perms),'exact parent read permission order')
        need(all(p['policy_allowed'] is False and p['denial_reason_mask']==1 for p in row['permissions'])
             and row['denial_reason_mask']==1 and row['requested']==row['denied_requested'],
             'every approved atom must be an original complete-AV TE denial')
        result.append(row)
    return result

def validate_parent_set_av(reader,plan):
    need(type(plan['parent_set_av_originals']) is list and len(plan['parent_set_av_originals'])==len(APPROVED_ROWS),
         'one fixed original parent set AV per reviewed type')
    result=[]
    for index,(src,target,_,_) in enumerate(APPROVED_ROWS):
        raw=reader.descriptor(plan['parent_set_av_originals'][index])
        need(sha(raw)==PARENT_SET_AV_PINS[index],'exact previously executed parent set AV original')
        row=strict(raw)
        need(row['schema']=='hepta.offline-policy-av.v1' and row['state']=='COMPLETE_OFFLINE_AV_QUERY'
             and row['policy']['sha256']==PARENT_SHA and row['policy']['bytes']==PARENT_BYTES
             and row['policy']['input_unchanged'] is True
             and row['query']['source']=='u:r:'+src+':s0' and row['query']['target']=='u:object_r:'+target+':s0'
             and row['query']['class']=='property_service'
             and row['query']['source_policy_permissive'] is False and row['query']['source_policy_neveraudit'] is False,
             'parent set AV context or original policy differs')
        need(len(row['permissions'])==1 and row['permissions'][0]['name']=='set'
             and row['permissions'][0]['policy_allowed'] is False and row['permissions'][0]['denial_reason_mask']==1
             and row['denial_reason_mask']==1 and row['requested']==row['denied_requested'],
             'the original property setter must remain an actual TE denial')
        result.append(row)
    return result

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--plan',type=Path,required=True);p.add_argument('--plan-sha256',required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--execute-host-only',action='store_true')
    a=p.parse_args(argv)
    if not a.execute_host_only:
        print(json.dumps({'state':'PREVIEW_NO_ORIGINAL_READ_NO_POLICY_PARSE','phone_operations':0,'active_policy_writes':0}));return 0
    require_reviewed_scope()
    os.umask(0o077);reader=Originals();selfpath=Path(__file__).resolve();selfraw=reader.read(selfpath)
    planraw=reader.read(a.plan,a.plan_sha256);plan=strict(planraw)
    required={'schema','root_scope_decision','parent_adoption','parent','candidate','image_build_result','live_provenance_inputs','live_verifier_source','applied_verifier_source','input_original_map','delta_rule','full_rule','parent_rule','tool_inventory','image_comparator','image_comparator_source','parent_av_originals','parent_set_av_originals','parent_apex_original','candidate_av_tool','candidate_av_source','secondary_observation'}
    need(set(plan)==required and plan['schema']=='hepta.runtime-properties-r10.post-live-complete-policy-comparison-plan.v2','exact comparison plan')
    parent=reader.descriptor(plan['parent']);cand=reader.descriptor(plan['candidate'])
    need(sha(parent)==PARENT_SHA and len(parent)==PARENT_BYTES and sha(cand)==plan['candidate']['sha256']
         and 0<len(cand)<=8*1024*1024,'exact current parent and explicit actual live export originals')
    decision=validate_decision_and_rules(reader,plan)
    live_provenance=validate_live_records(reader,plan)
    parent_av_originals=validate_parent_av(reader,plan)
    parent_set_originals=validate_parent_set_av(reader,plan)
    secondary_raw=reader.descriptor(plan['secondary_observation'])
    need(sha(secondary_raw)=='79afdcc1e87e2a13fc9c7276c136cd1937e4cf62d6f8a97d6f3ae162d42e2811',
         'exact second-level observation')
    secondary=strict(secondary_raw);apex=[r for r in secondary['directories'] if r['path']=='/apex']
    need(len(apex)==1 and apex[0]['kind']=='directory' and apex[0]['selinux']==
         {'raw_b64':'dTpvYmplY3RfcjphcGV4X21udF9kaXI6czAA','state':'XATTR_READ'},'exact observed APEX directory')
    invraw=reader.descriptor(plan['tool_inventory'])
    need(sha(invraw)=='b41918ef19a0c00b0ab2295c278f204b8d66c654e8dacad05db0dea232fbd288','reviewed exact 81-file tool inventory')
    inv=strict(invraw)
    need(inv['schema']=='hepta.existing-private-policy-tools.host-pin-inventory.v1' and len(inv['package_files'])==81,'existing exact tool inventory')
    for row in inv['package_files']:reader.descriptor(row)
    for row in inv['readers'].values():reader.descriptor(row)
    package=Path('/home/alex/razr60-local-runtime-v150/policy-tools-owned-v150-r1/unpack/usr/lib/python3/dist-packages')
    out=a.out.absolute();need(out.parent.resolve(strict=True)==out.parent and not out.exists() and not out.is_symlink(),'canonical new audit output parent')
    # -B alone permits reading old bytecode. A never-created private prefix
    # makes all pinned Python imports compile their checked source bytes.
    need(not any(name=='setools' or name.startswith('setools.') for name in sys.modules),'no preloaded package bypass')
    package,isolated_inventory,package_origin_map,package_tree=materialize_isolated_package(reader,package,inv,out)
    sys.pycache_prefix=str(out/'UNUSED-PYCACHE');sys.dont_write_bytecode=True
    need(not Path(sys.pycache_prefix).exists() and not Path(sys.pycache_prefix).is_symlink(),'unused fresh bytecode prefix')
    sys.path.insert(0,str(package));import setools
    import setools.policyrep
    import setools.exception
    need(Path(setools.__file__)==package/'setools/__init__.py','actual package import path')
    verify_loaded_package(reader,isolated_inventory)
    reader.descriptor(plan['image_comparator'])
    image_source=reader.descriptor(plan['image_comparator_source'])
    need(sha(image_source)==IMAGE_SOURCE_SHA and image_source==reader.read(Path(__file__).resolve().parent/'policy_runtime_properties_image.c'),'paired reviewed image source')
    reader.descriptor(plan['candidate_av_tool'])
    need(sha(reader.descriptor(plan['candidate_av_source']))=='262b264c79d12c1cd2af146808ac1c5998f6aa0159515a17796c381e12630a3c',
         'exact original complete AV source')
    need(plan['candidate_av_tool']['sha256']=='86f6d18eab7271d9a5688e5f7b03ed5b55740b9679e7dd078661573ad67f0c90','existing complete AV binary')
    library_pins=[{'path':'/usr/lib/x86_64-linux-gnu/libsepol.so.2','bytes':813368,'sha256':'c1e965eaae791bc4abc1fc2336a5433d7c483e5117778dbd06234b3fa9172092'},
        {'path':'/usr/lib/x86_64-linux-gnu/libcrypto.so.3','bytes':6386528,'sha256':'5385f0436ac2e284ba8c5fb1488874057c29c04be72dea32add832694f381e28'}]
    for row in library_pins:reader.descriptor(row)
    need(not os.environ.get('LD_PRELOAD') and not os.environ.get('LD_LIBRARY_PATH'),'no injected library environment')
    retained=[];checks=[]
    def put(name,raw):
        if not isinstance(raw,bytes):raw=encode(raw)
        q=out/name;fd=os.open(q,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
        need(q.read_bytes()==raw,'audit output readback');row={'path':str(q),'bytes':len(raw),'sha256':sha(raw)};retained.append(row);return row
    def check(name,passed,detail):checks.append({'name':name,'passed':bool(passed),'details':detail})
    def run(label,cmd,timeout=50):
        try:
            done=subprocess.run(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False,
                env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'})
        except subprocess.TimeoutExpired as exc:
            op=put(label+'.stdout.original',exc.stdout or b'');ep=put(label+'.stderr.original',exc.stderr or b'')
            put(label+'.PROCESS.json',{'argv':cmd,'returncode':None,'timed_out':True,'captured_streams_complete':False,
                'stdout':op,'stderr':ep,'automatic_retry':False,'host_only':True})
            raise
        op=put(label+'.stdout.original',done.stdout);ep=put(label+'.stderr.original',done.stderr)
        put(label+'.PROCESS.json',{'argv':cmd,'returncode':done.returncode,'timed_out':False,'captured_streams_complete':True,
            'stdout':op,'stderr':ep,'automatic_retry':False,'host_only':True})
        need(done.returncode==0 and done.stderr==b'','actual host reader failed: '+label)
        return strict(done.stdout)
    image_report=run('complete-image',[plan['image_comparator']['path'],'--compare-reviewed-runtime-properties',plan['parent']['path'],plan['candidate']['path'],str(out/'normalized')])
    need(image_report['schema']=='hepta.official-libsepol-runtime-properties-full-image-comparison.v1','complete image report schema')
    required_flags=('complete_input_consumption','baseline_conditional_list_empty','candidate_conditional_list_empty','all_cycles_close_at_first_image','all_cycle_representatives_stable','only_approved_delta_full_image_equal','negative_missing_atom_rejected','negative_unapproved_binder_change_rejected','negative_unknown_handling_rejected')
    need(all(image_report[k] is True for k in required_flags),'complete official-image equality or negative controls failed')
    need(image_report['approved_rule_atoms']==[list(a) for a in APPROVED_ATOMS]
         and image_report['approved_permission_atom_count']==len(APPROVED_ATOMS) and type(image_report['approved_new_allow_nodes']) is int
         and 0<=image_report['approved_new_allow_nodes']<=len(APPROVED_ROWS),'exact approved bits and bounded new AV keys')
    need(image_report['normalization']=='lexicographic-minimum-complete-official-serialization-cycle'
         and type(image_report['cycle_bound']) is int and image_report['cycle_bound']==4
         and type(image_report['raw_serializer_idempotent']) is bool,'fixed exact serializer cycle selection')
    need(image_report['baseline_boolean_count']==image_report['candidate_boolean_count']==image_report['baseline_conditional_avtab_nodes']==image_report['candidate_conditional_avtab_nodes']==0,'actual no-conditional coverage')
    normalized={}
    for label,name in (('parent','parent.normalized.bin'),('candidate','candidate.normalized.bin'),('expected','expected-approved-atoms.normalized.bin')):
        path=out/'normalized'/name;b=reader.read(path);normalized[label]={'path':str(path),'bytes':len(b),'sha256':sha(b)}
    need(normalized['candidate']['sha256']==normalized['expected']['sha256'] and normalized['candidate']['bytes']==normalized['expected']['bytes'],'complete expected/candidate canonical bytes differ')
    check('official-complete-image-only-approved-bits',True,image_report)
    snapshots={}
    for label,desc in (('parent',plan['parent']),('candidate',plan['candidate']),('parent_normalized',normalized['parent']),('candidate_normalized',normalized['candidate'])):
        policy=setools.SELinuxPolicy(desc['path']);s=policy_snapshot(policy,setools);snapshots[label]=s
        put(label+'.SNAPSHOT-SUMMARY.json',snapshot_summary(s))
        nonte={k:v for k,v in s.items() if k!='te_atoms'};put(label+'.non-te-tables.json.gz',gzip.compress(encode(nonte),mtime=0))
        if label in ('parent','candidate'):
            atomraw=b''.join(canonical([atom,count])+b'\n' for atom,count in sorted(s['te_atoms'].items()))
            put(label+'.all-te-atoms.jsonl.gz',gzip.compress(atomraw,mtime=0))
        del policy
    b=snapshots['parent'];c=snapshots['candidate']
    expected=Counter({(kind,src,target,cl,UNCONDITIONAL,'permission',perm):1 for kind,src,target,cl,perm in APPROVED_ATOMS})
    added=c['te_atoms']-b['te_atoms'];removed=b['te_atoms']-c['te_atoms']
    check('complete-TE-counter-exact-approved-unconditional-permissions',added==expected and not removed,{'added':sorted(added.items()),'removed':sorted(removed.items()),'parent':snapshot_summary(b)['te_atoms'],'candidate':snapshot_summary(c)['te_atoms']})
    other={k:{'equal':b[k]==c[k],'parent_sha256':sha(canonical(b[k])),'candidate_sha256':sha(canonical(c[k]))} for k in b if k not in ('te_atoms','te_raw_rule_count','te_kind_counts')}
    check('all-non-TE-and-symbol-memberships-exactly-preserved',all(x['equal'] for x in other.values()),other)
    for label in ('parent','candidate'):
        check(label+'-official-roundtrip-retains-all-enumerated-semantics',same_snapshot(snapshots[label],snapshots[label+'_normalized']),{'original':snapshot_summary(snapshots[label]),'normalized':snapshot_summary(snapshots[label+'_normalized'])})
    gap={}
    for label,desc in (('parent',plan['parent']),('candidate',plan['candidate']),('parent_normalized',normalized['parent']),('candidate_normalized',normalized['candidate'])):
        gap[label]={}
        for kind,row in inv['readers'].items():
            gap[label][kind]=run(label+'.'+kind,[row['path'],desc['path']],35)
    for table in ('roles','users','initialsids','fs_uses','unlabeled_filesystems'):
        values=[gap[label]['role_user'][table] for label in ('parent','candidate','parent_normalized','candidate_normalized')]
        check('complete-libsepol-'+table+'-and-roundtrips-preserved',all(v==values[0] for v in values),{'counts':[len(v) for v in values],'sha256':[sha(canonical(v)) for v in values]})
    values=[gap[label]['genfs']['genfs'] for label in ('parent','candidate','parent_normalized','candidate_normalized')]
    check('complete-genfs-path-class-context-and-roundtrips-preserved',all(v==values[0] for v in values),{'counts':[len(v) for v in values],'sha256':[sha(canonical(v)) for v in values]})
    # Every byte image in every admitted serializer cycle is retained and
    # independently reparsed. Equality of a selected representative alone
    # cannot hide a semantic change in an intermediate image.
    expected_snapshot={**b,'te_atoms':b['te_atoms']+expected,
        'te_raw_rule_count':b['te_raw_rule_count']+image_report['approved_new_allow_nodes'],
        'te_kind_counts':dict(b['te_kind_counts'])}
    expected_snapshot['te_kind_counts']['allow']+=image_report['approved_new_allow_nodes']
    orbit_names=['parent','candidate','expected','negative-handle-unknown','negative-binder-change']
    orbit_rows=image_report['serialization_orbits']
    need([row['name'] for row in orbit_rows]==orbit_names,'exact serializer orbit set')
    orbit_evidence=[]
    summary_cache={plan['parent']['sha256']:snapshot_summary(b),plan['candidate']['sha256']:snapshot_summary(c),
        normalized['parent']['sha256']:snapshot_summary(snapshots['parent_normalized']),
        normalized['candidate']['sha256']:snapshot_summary(snapshots['candidate_normalized'])}
    reader_cache={plan['parent']['sha256']:gap['parent'],plan['candidate']['sha256']:gap['candidate'],
        normalized['parent']['sha256']:gap['parent_normalized'],normalized['candidate']['sha256']:gap['candidate_normalized']}
    for orbit in orbit_rows:
        name=orbit['name'];length=orbit['length'];selected=orbit['selected_index']
        need(set(orbit)=={'name','length','selected_index'} and type(length) is int and 1<=length<=4
             and type(selected) is int and 1<=selected<=length,'bounded closed first-image orbit')
        images=[];first_summary=None
        reference={'parent':b,'candidate':c,'expected':expected_snapshot}.get(name)
        for index in range(1,length+1):
            path=out/'normalized'/(name+'.orbit-'+str(index).zfill(2)+'.bin');raw=reader.read(path)
            row={'path':str(path),'bytes':len(raw),'sha256':sha(raw)};images.append((raw,row))
            summary=summary_cache.get(row['sha256'])
            if summary is None or (first_summary is None and reference is None):
                policy=setools.SELinuxPolicy(str(path));member=policy_snapshot(policy,setools);summary=snapshot_summary(member)
                if first_summary is None and reference is None:
                    if name=='negative-handle-unknown':
                        need(all(member[k]==expected_snapshot[k] for k in member if k!='metadata')
                             and all(member['metadata'][k]==expected_snapshot['metadata'][k] for k in member['metadata'] if k!='handle_unknown')
                             and member['metadata']['handle_unknown']!=expected_snapshot['metadata']['handle_unknown'],
                             'negative metadata image is not only the declared unknown-handling mutation')
                    else:
                        changed=Counter({('allow',WORKER,ALLOCATOR,'binder',UNCONDITIONAL,'permission','transfer'):1})
                        direction=image_report['negative_binder_change_direction'];need(direction in ('add','remove'),'known negative AV direction')
                        want=expected_snapshot['te_atoms']+changed if direction=='add' else expected_snapshot['te_atoms']-changed
                        need(member['te_atoms']==want and all(member[k]==expected_snapshot[k] for k in member
                            if k not in ('te_atoms','te_raw_rule_count','te_kind_counts')),
                             'negative AV image contains an undeclared semantic mutation')
                        count_delta=0 if image_report['negative_binder_had_exact_allow_key'] else 1
                        want_kinds=dict(expected_snapshot['te_kind_counts']);want_kinds['allow']+=count_delta
                        need(member['te_raw_rule_count']==expected_snapshot['te_raw_rule_count']+count_delta
                             and member['te_kind_counts']==want_kinds,'negative AV raw rule inventory differs')
                summary_cache[row['sha256']]=summary;del member;del policy
            if first_summary is None:
                first_summary=summary
                if reference is not None:need(summary==snapshot_summary(reference),'first serializer image lost original or expected complete table semantics')
                else:need(row['sha256'] not in {normalized['parent']['sha256'],normalized['candidate']['sha256']},'negative collapsed onto an authorized policy')
            need(summary==first_summary,'serializer cycle intermediate image changed table semantics')
            supplement=reader_cache.get(row['sha256'])
            if supplement is None:
                supplement={kind:run(name+'.orbit-'+str(index).zfill(2)+'.'+kind,[tool['path'],str(path)],35)
                    for kind,tool in inv['readers'].items()};reader_cache[row['sha256']]=supplement
            need(supplement==gap['parent'],'serializer cycle changed complete role/user/object/genfs structures')
        least=min(raw for raw,row in images)
        need(images[selected-1][0]==least and len({row['sha256'] for raw,row in images})==length,
             'cycle representative is not the fixed minimum or a member was duplicated before closure')
        if name in normalized:need(images[selected-1][1]['sha256']==normalized[name]['sha256'],'saved representative differs from actual complete cycle')
        orbit_evidence.append({'name':name,'length':length,'selected_index':selected,
            'original_images':[row for raw,row in images],'complete_table_semantics_sha256':sha(canonical(first_summary)),
            'all_members_complete_tables_and_supplemental_readers_equal':True})
    check('every-first-image-closed-orbit-member-preserves-complete-structure-and-semantics',True,orbit_evidence)
    # The exact original parent computations remain raw history. Only the
    # newly constructed candidate is queried here, for the approved subset.
    candidate_av_rows=[];av_ok=True
    for index,((src,target,cl,perms),parent_av) in enumerate(zip(APPROVED_ROWS,parent_av_originals)):
        target_context=('u:r:' if cl=='binder' else 'u:object_r:')+target+':s0'
        argv=[plan['candidate_av_tool']['path'],'--policy',plan['candidate']['path'],'--sha256',plan['candidate']['sha256'],
              '--source','u:r:'+src+':s0','--target',target_context,'--class',cl]
        for perm in perms:argv.extend(['--perm',perm])
        candidate_av=run('candidate-complete-av-'+str(index+1).zfill(2),argv)
        need(candidate_av['schema']=='hepta.offline-policy-av.v1' and candidate_av['state']=='COMPLETE_OFFLINE_AV_QUERY'
             and candidate_av['policy']['sha256']==plan['candidate']['sha256']
             and candidate_av['policy']['bytes']==plan['candidate']['bytes'] and candidate_av['policy']['input_unchanged'] is True
             and candidate_av['query']==parent_av['query']
             and candidate_av['engine']['source_sha256']==plan['candidate_av_source']['sha256'],
             'candidate full AV original context and policy identity')
        need([p['name'] for p in candidate_av['permissions']]==list(perms),'exact approved candidate query subset')
        requested=0
        parent_perms={p['name']:p for p in parent_av['permissions']}
        for perm in candidate_av['permissions']:
            requested|=int(perm['bit'],16)
            av_ok=av_ok and perm['policy_allowed'] is True and perm['denial_reason_mask']==0
            av_ok=av_ok and all(perm[k]==parent_perms[perm['name']][k] for k in
                ('name','bit','auditallow_bit','auditdeny_bit','denied_with_auditdeny_clear'))
        av_ok=av_ok and int(candidate_av['requested'],16)==requested
        av_ok=av_ok and (int(candidate_av['allowed'],16)&requested)==requested
        av_ok=av_ok and candidate_av['denied_requested']=='0x00000000' and candidate_av['denial_reason_mask']==0
        av_ok=av_ok and all(candidate_av[k]==parent_av[k] for k in ('decided','auditallow','auditdeny'))
        candidate_av_rows.append(candidate_av)
    check('candidate-complete-libsepol-AV-all-reasons-allow-exact-approved-bits',av_ok,
          {'parent_originals':plan['parent_av_originals'],'candidate_originals':candidate_av_rows,'parent_reexecuted':False})
    effective={}
    for index,(src,target,cl,perms) in enumerate(APPROVED_ROWS):
        pair={}
        for label,desc in (('parent',plan['parent']),('candidate',plan['candidate'])):
            policy=setools.SELinuxPolicy(desc['path'])
            rules=list(setools.TERuleQuery(policy,ruletype=[setools.TERuletype.allow],source=src,source_indirect=True,
                                         target=target,target_indirect=True,tclass=[cl]).results())
            pair[label]={'rules':[str(r) for r in rules],'permissions':sorted({str(p) for r in rules for p in r.perms})}
            del policy
        need(set(pair['parent']['permissions']).isdisjoint(perms)
             and set(pair['candidate']['permissions'])==set(pair['parent']['permissions'])|set(perms),
             'expanded symbolic effective edge has more than the approved permission delta')
        effective[str(index+1)]={'source':src,'target':target,'class':cl,'approved_permissions':list(perms),**pair}
    check('exact-effective-unconditional-approved-edges-in-symbolic-expanded-policy',True,effective)
    need(plan['parent_apex_original']['sha256']=='34fc5fe1e5278b07ff80b80de8b0cf3c8a4bbaaf5ca3518a9095a2e3ed78d6b7'
         and plan['parent_apex_original']['bytes']==2196,'fixed actual APEX original')
    parent_apex=strict(reader.descriptor(plan['parent_apex_original']))
    need(parent_apex['schema']=='hepta.offline-policy-av.v1' and parent_apex['state']=='COMPLETE_OFFLINE_AV_QUERY'
         and parent_apex['policy']['sha256']==PARENT_SHA and parent_apex['policy']['bytes']==PARENT_BYTES
         and parent_apex['query']['source']=='u:r:'+WORKER+':s0'
         and parent_apex['query']['target']=='u:object_r:apex_mnt_dir:s0' and parent_apex['query']['class']=='dir'
         and [p['name'] for p in parent_apex['permissions']]==['search']
         and parent_apex['permissions'][0]['policy_allowed'] is True and parent_apex['denial_reason_mask']==0,
         'actual original observed APEX search must already be allowed')
    candidate_apex=run('candidate-existing-apex-search',[plan['candidate_av_tool']['path'],'--policy',plan['candidate']['path'],
         '--sha256',plan['candidate']['sha256'],'--source','u:r:'+WORKER+':s0',
         '--target','u:object_r:apex_mnt_dir:s0','--class','dir','--perm','search'])
    need(candidate_apex['policy']['sha256']==plan['candidate']['sha256'] and candidate_apex['policy']['input_unchanged'] is True,
         'candidate APEX query input')
    apex_keys=('query','requested','allowed','denied_requested','denial_reason_mask','decided','auditallow','auditdeny','permissions')
    check('observed-apex-search-remains-identical-allow-without-new-atom',
          all(parent_apex[k]==candidate_apex[k] for k in apex_keys),
          {'parent_original':plan['parent_apex_original'],'candidate':candidate_apex,'new_apex_rule_added':False})
    candidate_set_rows=[]
    set_keys=('query','requested','allowed','denied_requested','denial_reason_mask','decided',
              'auditallow','auditdeny','permissions','constraint_explanation','reason_flag_definitions')
    for index,((src,target,_,_),parent_set) in enumerate(zip(APPROVED_ROWS,parent_set_originals)):
        row=run('candidate-property-set-deny-'+str(index+1).zfill(2),
            [plan['candidate_av_tool']['path'],'--policy',plan['candidate']['path'],'--sha256',plan['candidate']['sha256'],
             '--source','u:r:'+src+':s0','--target','u:object_r:'+target+':s0','--class','property_service','--perm','set'])
        need(row['schema']=='hepta.offline-policy-av.v1' and row['state']=='COMPLETE_OFFLINE_AV_QUERY'
             and row['policy']['sha256']==plan['candidate']['sha256']
             and row['policy']['bytes']==plan['candidate']['bytes'] and row['policy']['input_unchanged'] is True
             and row['engine']['source_sha256']==plan['candidate_av_source']['sha256'],
             'candidate property-set query original policy or tool differs')
        need(all(row[k]==parent_set[k] for k in set_keys),'property setter decision or audit behavior changed')
        candidate_set_rows.append(row)
    check('approved-property-service-set-remains-identical-deny',True,
          {'parent_originals':plan['parent_set_av_originals'],'candidate_originals':candidate_set_rows,
           'parent_reexecuted':False,'new_set_permissions':0})
    need(len(checks)==16,'all fifteen complete-comparison families plus the exact setter-denial gate required')
    need(all(x['passed'] for x in checks),'one or more complete comparison checks failed')
    loaded_package=verify_loaded_package(reader,isolated_inventory)
    need(verify_closed_package_tree(reader,package,isolated_inventory)==package_tree,'exact private importable package tree changed')
    need(not Path(sys.pycache_prefix).exists() and sys.dont_write_bytecode is True,'unexpected bytecode cache')
    reader.recheck()
    report={'schema':'hepta.runtime-properties-r10.complete-policy-comparison.v1','state':'EXACT_APPROVED_RUNTIME_PROPERTY_READ_DELTA_VERIFIED',
        'comparison_kind':'post_live_export','parent':plan['parent'],'candidate':plan['candidate'],
        'root_scope_decision':plan['root_scope_decision'],'parent_adoption_history':plan['parent_adoption'],
        'approved_rule_atoms':[list(a) for a in APPROVED_ATOMS],'semantic_delta':{'added_atoms':[list(a) for a in APPROVED_ATOMS],'removed_atoms':[],
          'all_raw_TE_counter_delta_bound':True,'unconditional_only':True,'added_counter_sha256':atom_digest(added),'removed_counter_sha256':atom_digest(removed)},
        'coverage':{'all_TE_rules_enumerated':True,'multiplicity_preserved':True,'conditional_expression_and_branch_preserved':True,
          'explicit_xperm_type_and_all_integers':True,'non_TE_tables':list(NON_TE_TABLES),
          'additional_complete_tables':['types','type_attributes','booleans','classes_with_common','common_permissions','conditionals','roles','users','initialsids','fs_uses','unlabeled_filesystems','genfs'],
          'actual_conditional_list_empty':True,'actual_conditional_avtab_count':0,'unsupported_rule_kinds':[],'errors':[]},
        'full_image_comparison':{'result':image_report,'normalized_originals':normalized,'all_enumerated_roundtrip_semantics_preserved':True,
          'serialization_orbits':orbit_evidence,'all_orbit_members_structurally_and_semantically_verified':True,
          'normalization_scope':'The complete supported v30 kernel policy is serialized by the same installed libsepol. A fixed bound of four requires an exact byte cycle closing at its first image; the entire cycle is retained and its lexicographic minimum selected. Every member is independently checked against complete tables and supplemental readers. This does not claim raw serialization is a single-step fixed point.'},
        'full_av_checks':{'all_compiled_AV_nodes_validated':True,'all_symbolic_AV_permission_atoms_compared':True,
          'parent_original_compute_av':plan['parent_av_originals'],'parent_original_query_reexecuted':False,
          'candidate_complete_compute_av':candidate_av_rows,'candidate_complete_compute_av_verified':True,
          'candidate_approved_permission_count':len(APPROVED_ATOMS),
          'parent_original_set_av':plan['parent_set_av_originals'],'candidate_complete_set_av':candidate_set_rows,
          'all_reviewed_property_set_denials_unchanged':True,'existing_apex_search_unchanged':True,'existing_fd_use_preserved_by_complete_TE_counter':True,
          'runtime_libraries':library_pins},
        'checks':checks,'check_count':len(checks),'passed_count':len(checks),'effective':effective,
        'post_live_originals':live_provenance,
        'sources':{'comparator':{'path':str(selfpath),'bytes':len(selfraw),'sha256':sha(selfraw)},
          'image_comparator':plan['image_comparator'],'image_comparator_source':plan['image_comparator_source'],'existing_tools':plan['tool_inventory'],
          'candidate_av_tool':plan['candidate_av_tool'],'candidate_av_source':plan['candidate_av_source'],
          'live_provenance_verifier':plan['live_verifier_source'],'applied_verifier_source':plan['applied_verifier_source'],
          'image_build_result':plan['image_build_result']},
        'package_tree_provenance':{'closed_tree':package_tree,'loaded_original_modules':loaded_package,'unindexed_entries':[],
          'source_inventory':plan['tool_inventory'],'source_to_private_copy_map':package_origin_map,
          'original_import_tree_closed_claimed':False,'original_import_path_added_to_sys_path':False,
          'fresh_unused_bytecode_prefix':sys.pycache_prefix,'complete_tree_and_origins_rechecked':True},
        'input_originals_rechecked':len(reader.seen),'retained_originals':retained.copy(),
        'phone_operations':0,'active_policy_writes':0,'live_policy_adoption_authorized':False,'business_qualified':False,
        'limitations':['This compares the independently captured actual live export after verifying the complete original transaction chain; it does not adopt policy or qualify a screenshot.',
          'Root must separately and explicitly adopt the verified actual exported bytes.',
          'The helper admits the actual v30 MLS conditional-free format; unknown rule kinds or nonempty conditional storage are rejected.']}
    row=put('RESULT.json',report);fd=os.open(out,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    print(json.dumps({'state':report['state'],'checks':len(checks),'result':row,'new_atoms':len(APPROVED_ATOMS),'removed_atoms':0,'phone_operations':0,'active_policy_writes':0},sort_keys=True));return 0

if __name__=='__main__':raise SystemExit(main())
