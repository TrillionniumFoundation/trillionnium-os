#!/usr/bin/env python3
"""Exact pure snapshot/business/restoration projections; no effect entrypoint."""
import ast,base64,copy,datetime,fnmatch,hashlib,json,re,shlex,types
from pathlib import PurePosixPath
import fault_originals as O
ROOT='/negative-retained-view'
need=O.need
sha=O.sha
strict=O.strict
same=O.same
def zero(v):return type(v) is int and v==0
def projected(raw, names, constants=(), namespace=None):
    """Exact pinned raw function/constant projection; no source imports."""
    tree=ast.parse(raw);body=[];seen=set()
    for node in tree.body:
        if isinstance(node,(ast.FunctionDef,ast.ClassDef)) and node.name in names:
            body.append(copy.deepcopy(node));seen.add(node.name)
        elif isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
            key=node.targets[0].id
            if key in constants:
                body.append(copy.deepcopy(node));seen.add(key)
    need(seen==set(names)|set(constants),'pure_source_projection_closed_set')
    ns=dict(namespace or {})
    exec(compile(ast.Module(body=body,type_ignores=[]),'<exact-pinned-pure-projection>','exec'),ns)
    return types.SimpleNamespace(**ns)

class FrozenSnapshot:
    """Closed archive view. A missing member is never silently treated as ENOENT."""
    def __init__(self,context):
        self.context=context;phone=context['phone']
        self.files={ROOT+'/'+name:raw for name,raw in phone['members'].items()}
        self.absences={ROOT+'/'+row['export_relative_path'] for row in phone['capture']['files']
                       if row.get('state')=='absent' and row.get('lookup_errno')==2}
        self.directories={}
        for row in phone['capture']['directories']:
            source=row['source_path']
            if source.startswith(O.BASE+'/') and row.get('state')=='observed':
                path=ROOT+'/'+source[len(O.BASE)+1:]
                old=self.directories.get(path)
                need(old is None or same(old,row),'source_directory_views_changed')
                self.directories[path]=row
        owner=self
        class ArchivePath(PurePosixPath):
            def glob(self,pattern):
                need('/' not in pattern and '**' not in pattern,'closed_nonrecursive_glob')
                return iter(ArchivePath(k) for k in sorted(owner.files)
                            if PurePosixPath(k).parent==self and fnmatch.fnmatchcase(PurePosixPath(k).name,pattern))
        self.Path=ArchivePath
    def read(self,path,required=True,maximum=O.MAX_FILE):
        text=str(path);need(text.startswith(ROOT+'/') and '..' not in PurePosixPath(text).parts,
                           'closed_snapshot_path')
        if text in self.files:
            raw=self.files[text];need(len(raw)<=maximum,'snapshot_read_bound');return raw
        if not required:
            parent=self.directories.get(str(PurePosixPath(text).parent))
            absent=text in self.absences or parent is not None and PurePosixPath(text).name not in parent['names']
            need(absent,'missing_archive_is_not_original_absence')
            return None
        raise O.Unverified('required_original_missing')
    def json(self,path,required=True,maximum=O.MAX_FILE):
        raw=self.read(path,required=required,maximum=maximum)
        return None if raw is None else strict(raw)
    def pinned(self,path,pin,maximum=O.MAX_FILE):
        raw=self.read(path,maximum=maximum);need(sha(raw)==pin,'snapshot_original_pin');return raw

def business_api(context,snapshot):
    return projected(context['raw_sources']['business'],
        {'sha','require','compact','decode64','streams','native_tool_streams',
         'r6_journal_binding','r6_terminal_identity_and_cleanup','inspect_tool'},
        {'MUTATIONS','SAFE_STATES','R6_CLIENT_SOURCE_SHA256','R6_ENDPOINT','R6_PARENT','R6_BOOTSTRAP'},
        dict(base64=base64,hashlib=hashlib,json=json,re=re,Path=snapshot.Path,
             strict_loads=strict,SCOPE_FIELDS=O.SCOPE))

def private_restoration(originals,label,preserved_raw):
 original=strict(preserved_raw)
 need(isinstance(original,dict) and isinstance(original.get('exact_utf8_b64'),str),'private original draft shape')
 draft=base64.b64decode(original['exact_utf8_b64'],validate=True);draft.decode('utf-8',errors='strict')
 need(draft and sha(draft)==original['utf8_sha256'],'private original draft integrity')
 result=originals['DRAFT-RESTORE-RESULT.json'];wire=originals['PRESERVED-DRAFT-RESTORE.original.json']
 need(result.get('state')=='ORIGINAL_DRAFT_RESTORED' and result.get('original_draft_submitted') is False
      and result.get('model_business_credit') is False and result.get('restore_attempts')==1
      and result.get('utf8_sha256')==sha(draft),'original cleanup disposition')
 need(zero(wire.get('rc')) and wire.get('stderr')=='','original draft restore wire not terminal zero')
 value=strict(wire['stdout'])
 need(value.get('schema')=='hepta.focused-unicode-input.v1' and value.get('status') in ('set_verified','already_exact')
      and value.get('operation_id')=='root-restore-'+label and value.get('display_id')==0
      and value.get('package')=='org.trillionnium.owneropen'
      and value.get('view_id')=='org.trillionnium.owneropen:id/ui_prompt'
      and value.get('own_automation_disconnected') is True,'original cleanup action binding')
 readback=base64.b64decode(value['readback_text_b64'],validate=True)
 need(readback==draft and value.get('requested_utf8_sha256')==sha(draft)
      and value.get('after_utf8_sha256')==sha(draft),'private exact draft readback differs')
 return {'exact_original_draft_restored':True,'original_draft_submitted':False,
         'restore_attempts':1,'business_return_credit':False,'private_text_or_digest_in_public_output':False}
