#!/usr/bin/env python3
"""Check the owner/sealed SDK selectors with a deliberately bounded BP parser.

This verifies source configuration only. It does not run Soong, prove the entire
classpath closure, inspect a compiled resource table or qualify installation.
The sealed property contract retains the existing module inputs; it is not an
Android API signature file and does not replace any API or compatibility check.
"""
from __future__ import annotations
import argparse,copy,json,os,re,stat,sys,xml.etree.ElementTree as ET
from pathlib import Path,PurePosixPath

TOKEN = re.compile(r'\s+|//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|[A-Za-z_][A-Za-z0-9_]*|\d+|[{}\[\]:,+]',re.S)

class Parser:
    def __init__(self,text):
        self.tokens=[];position=0
        for m in TOKEN.finditer(text):
            if m.start()!=position:raise ValueError('unsupported Blueprint token at '+str(position))
            position=m.end();v=m.group()
            if v.isspace() or v.startswith('//') or v.startswith('/*'):continue
            self.tokens.append(v)
            if len(self.tokens)>32768:raise ValueError('Blueprint token bound exceeded')
        if text[position:].strip():raise ValueError('trailing unsupported token')
        self.i=0
    def take(self,wanted=None):
        v=self.tokens[self.i];self.i+=1
        if wanted is not None and v!=wanted:raise ValueError('expected '+wanted+' got '+v)
        return v
    def value(self):
        v=self.take()
        if v=='{':
            out={}
            while self.tokens[self.i]!='}':
                name=self.take();self.take(':')
                if name in out:raise ValueError('duplicate property')
                out[name]=self.value()
                if self.tokens[self.i]==',':self.take(',')
                elif self.tokens[self.i]!='}':raise ValueError('missing property separator')
            self.take('}')
        elif v=='[':
            out=[]
            while self.tokens[self.i]!=']':
                out.append(self.value())
                if self.tokens[self.i]==',':self.take(',')
                elif self.tokens[self.i]!=']':raise ValueError('missing list separator')
            self.take(']')
        elif v.startswith('"'):out=json.loads(v)
        elif v in ('true','false'):out=v=='true'
        elif v.isdigit():out=int(v)
        else:raise ValueError('unsupported expression '+v)
        if self.i<len(self.tokens) and self.tokens[self.i]=='+':
            self.take('+');right=self.value()
            if type(out) is not type(right) or type(out) not in (str,list):
                raise ValueError('only same-type Blueprint string/list concatenation is supported')
            out=out+right
        return out
    def modules(self):
        out=[]
        while self.i<len(self.tokens):out.append((self.take(),self.value()))
        return out

def modules(text):
    out={}
    for kind,value in Parser(text).modules():
        if not isinstance(value,dict):raise ValueError('Blueprint module body must be a property map')
        if 'name' not in value:continue
        if value['name'] in out:raise ValueError('duplicate module declaration')
        out[value['name']]=(kind,value)
    return out

def typed_equal(left,right):
    # Python False == 0 is not a Blueprint bool/integer type match.
    if type(left) is not type(right):return False
    if isinstance(left,dict):
        return left.keys()==right.keys() and all(typed_equal(v,right[k]) for k,v in left.items())
    if isinstance(left,(list,tuple)):
        return len(left)==len(right) and all(typed_equal(a,b) for a,b in zip(left,right))
    return left==right

def project(value,enabled):
    # This follows the actual observed bool/default branch and append semantics.
    # A real Soong build remains required to qualify the full input graph.
    out=copy.deepcopy(value);variables=out.pop('soong_config_variables',{})
    if variables:
        branch=variables['enabled']
        chosen={k:v for k,v in branch.items() if k!='conditions_default'} if enabled else branch.get('conditions_default',{})
        for name,items in chosen.items():out[name]=out.get(name,[])+copy.deepcopy(items)
    return out

SEALED_MODULE_PROPERTIES = {'org.trillionnium.platform-res': {'name': 'org.trillionnium.platform-res', 'use_resource_processor': False, 'sdk_version': 'core_platform', 'certificate': 'platform', 'manifest': 'trillionnium/res/AndroidManifest.xml', 'enforce_uses_libs': False, 'dex_preopt': {'enabled': False}, 'aaptflags': ['--private-symbols', 'org.trillionnium.platform.internal', '--no-auto-version', '--auto-add-overlay', '--allow-reserved-package-id', '--package-id', '63'], 'resource_dirs': ['trillionnium/res/res'], 'export_package_resources': True}, 'org.trillionnium.platform': {'name': 'org.trillionnium.platform', 'defaults': ['trillionnium-sdk-defaults'], 'installable': True, 'sdk_version': 'core_platform', 'libs': ['framework', 'framework-connectivity.stubs.module_lib', 'services'], 'srcs': [':trillionnium-platform-library-sources'], 'static_libs': ['trillionnium-agent-identity-product', 'trillionnium-capability-lease-binder-api'], 'exclude_srcs': ['trillionnium/lib/main/java/org/trillionnium/platform/internal/CapabilityLeaseRootRouteSocketConnectorV1.java', 'trillionnium/lib/main/java/org/trillionnium/platform/internal/CapabilityLeaseRootRouteSessionConstructorV1.java', 'trillionnium/lib/main/java/org/trillionnium/platform/internal/CapabilityLeasePluginAdapterV1.java', 'trillionnium/lib/main/java/org/trillionnium/platform/internal/CapabilityLeasePluginDexStructureV1.java', 'trillionnium/lib/main/java/org/trillionnium/platform/internal/CapabilityLeasePluginJarStructureV1.java', 'trillionnium/lib/main/java/org/trillionnium/platform/internal/CapabilityLeaseVerifiedPluginAndroidBackendV1.java', 'trillionnium/lib/main/java/org/trillionnium/platform/internal/CapabilityLeaseVerifiedPluginLoaderV1.java', 'trillionnium/lib/main/java/org/trillionnium/platform/internal/CapabilityLeaseOsNetworkTlsEffectV1.java', 'trillionnium/lib/main/java/org/trillionnium/platform/internal/CapabilityLeaseSelectedNetworkTlsProducerV1.java', 'trillionnium/lib/main/java/org/trillionnium/platform/internal/CapabilityLeaseAndroidSelectedNetworkTlsProducerV1.java'], 'required': ['org.trillionnium.agent.system_api.xml']}}
SDK_DEFAULT_PROPERTIES = {'name': 'trillionnium-sdk-defaults', 'aidl': {'local_include_dirs': ['sdk/src/java']}, 'srcs': [':trillionnium-sdk-internal-sources', ':trillionnium-sdk-sources', ':org.trillionnium.platform-res{.aapt.srcjar}'], 'static_libs': ['vendor.trillionnium.health-V2-java', 'vendor.trillionnium.livedisplay-V1-java', 'vendor.trillionnium.touch-V1-java']}
OWNER_EXCLUDES = [
    "trillionnium/lib/main/java/org/trillionnium/platform/internal/AgentSystemApi*.java",
    "trillionnium/lib/main/java/org/trillionnium/platform/internal/CapabilityLease*.java",
    "trillionnium/lib/main/java/org/trillionnium/platform/internal/OpenUriLeaseSemanticsV1*.java",
    "trillionnium/lib/main/java/org/trillionnium/platform/internal/plugin/*.java",
]
OWNER_SERVICES = [
    "org.trillionnium.platform.internal.ProfileManagerService",
    "org.trillionnium.platform.internal.TrillionniumHardwareService",
    "org.trillionnium.platform.internal.display.LiveDisplayService",
    "org.trillionnium.platform.internal.TrustInterfaceService",
    "org.trillionnium.platform.internal.TrillionniumSettingsService",
    "org.trillionnium.platform.internal.TrillionniumGlobalActionsService",
    "org.trillionnium.platform.internal.health.HealthInterfaceService",
]
PREFIX = "android-integration/working-tree/"
BP = PREFIX+"trillionnium-sdk/Android.bp"
OWNER_XML = PREFIX+"trillionnium-sdk/owner-open/res/values/config.xml"
PRODUCT = PREFIX+"vendor/trillionnium/owner-open/product.mk"
MAX_BYTES = 256*1024

OWNER_BOOL = "$(call soong_config_set_bool,trillionnium_owner_open,enabled,true)"
OWNER_MAKE_CONDITIONS = [
    "ifeq ($(TRILLINNIUM_DOGFOOD_USERDEBUG_ADB_ROOT),true)",
    "ifneq ($(filter userdebug eng,$(TARGET_BUILD_VARIANT)),)",
]
OWNER_LOCAL_VARS = ["_TRILLIONNIUM_OWNER_OPEN_FORBIDDEN_PACKAGES",
                    "_TRILLIONNIUM_OWNER_OPEN_RETIRED_CLIENTS"]

def owner_product_bool(text):
    """Accept only the finite owned product grammar, with one top-level bool.

    This does not evaluate arbitrary Make, Kati or inherited product nodes.
    Rejecting unknown statements prevents an indirect setter, conditional,
    definition or later registry assignment from silently undoing the bool.
    The licensed real Make fixture separately tests this restricted grammar.
    """
    if not text.isascii() or any(ord(c)<32 and c not in "\n\t" or ord(c)==127 for c in text):
        raise ValueError("unsupported owner product Make control/non-ASCII character")
    statements=[];pending=""
    for raw in text.split("\n"):
        if "#" in raw and raw.rstrip().endswith("\\"):
            raise ValueError("owner product comment continuation is unsupported")
        if raw.startswith("\t") and not pending and not raw.lstrip().startswith("#"):
            raise ValueError("new owner product statement cannot start with recipe TAB")
        line=raw.split("#",1)[0].strip()
        if not line and not pending:continue
        continued=line.endswith("\\")
        pending+=line[:-1]+" " if continued else line
        if continued:continue
        if pending.strip():statements.append(pending.strip())
        pending=""
    if pending:raise ValueError("unfinished owner product continuation")
    depth=[];bool_count=0
    for line in statements:
        if line==OWNER_BOOL:
            if depth:raise ValueError("owner build bool must be unconditional")
            bool_count+=1;continue
        if line in OWNER_MAKE_CONDITIONS:
            if len(depth)>=2 or line!=OWNER_MAKE_CONDITIONS[len(depth)]:
                raise ValueError("unsupported owner product condition nesting")
            depth.append(line);continue
        if line=="endif":
            if not depth:raise ValueError("unmatched owner product endif")
            depth.pop();continue
        assignment=re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\s*(:=|\+=)\s*(.*)",line)
        if not assignment:raise ValueError("unsupported owner product Make statement")
        name,operator,value=assignment.groups()
        if name in OWNER_LOCAL_VARS and operator==":=":
            valid=not depth and (not value or re.fullmatch(r"[A-Za-z0-9_.+-]+(?:\s+[A-Za-z0-9_.+-]+)*",value))
        elif name in ("PRODUCT_PACKAGES","PRODUCT_PACKAGES_DEBUG") and operator==":=":
            valid=not depth and value in ["$(filter-out $("+v+"),$("+name+"))" for v in OWNER_LOCAL_VARS]
        elif operator=="+=" and name in ("PRODUCT_PACKAGES","SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS","PRODUCT_SYSTEM_EXT_PROPERTIES"):
            valid=bool(re.fullmatch(r"[A-Za-z0-9_./=+-]+(?:\s+[A-Za-z0-9_./=+-]+)*",value))
            if depth:
                valid=valid and len(depth)==2 and (
                    (name=="PRODUCT_PACKAGES" and value=="adb_root") or
                    (name=="SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS" and value=="vendor/trillionnium/owner-open/sepolicy/adbroot"))
        else:valid=False
        if not valid:raise ValueError("unsupported owner product assignment or expansion: "+name)
    if depth:raise ValueError("unclosed owner product conditional")
    if bool_count!=1:raise ValueError("owner build bool declaration missing or duplicated")

def read(root,relative):
    rel=PurePosixPath(relative)
    if rel.is_absolute() or str(rel)!=relative or '..' in rel.parts:
        raise ValueError("canonical relative source path required")
    root_path=root.resolve(strict=True);path=root_path/relative
    def identity(s):
        return (s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink,s.st_uid,s.st_gid)
    dir_flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC
    descriptors=[]
    try:
        parent=os.open(root_path,dir_flags);descriptors.append(parent)
        for component in rel.parts[:-1]:
            parent=os.open(component,dir_flags,dir_fd=parent);descriptors.append(parent)
        parent_path=path.parent.resolve(strict=True)
        if not parent_path.is_relative_to(root_path):raise ValueError("source path escapes root")
        before=os.stat(rel.name,dir_fd=parent,follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or not 0<before.st_size<=MAX_BYTES:
            raise ValueError("source must be a bounded ordinary file: "+relative)
        fd=os.open(rel.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
        descriptors.append(fd);opened=os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or identity(opened)!=identity(before):
            raise ValueError("source entry changed before open: "+relative)
        chunks=[];total=0
        while True:
            block=os.read(fd,min(65536,MAX_BYTES-total+1))
            if not block:break
            total+=len(block)
            if total>MAX_BYTES:raise ValueError("actual source read exceeds byte bound: "+relative)
            chunks.append(block)
        after_fd=os.fstat(fd);after_entry=os.stat(rel.name,dir_fd=parent,follow_symlinks=False)
        current=path.lstat()
        if (total!=opened.st_size or identity(after_fd)!=identity(opened)
            or identity(after_entry)!=identity(opened) or identity(current)!=identity(opened)
            or path.parent.resolve(strict=True)!=parent_path
            or not path.resolve(strict=True).is_relative_to(root_path)):
            raise ValueError("source FD/entry or root containment changed: "+relative)
        return b''.join(chunks).decode("utf-8")
    finally:
        for fd in reversed(descriptors):os.close(fd)

def verify(root):
    root=Path(root)
    facts={"source_configuration_only":True,"actual_soong_compiled":False,
        "full_sdk_classpath_closure_qualified":False,"compiled_resources_qualified":False,
        "api_validation_disabled":False,"installed":False,"production_ready":False}
    try:
        sdk=modules(read(root,BP))
        definitions={"trillionnium_owner_open_android_app":("android_app",["resource_dirs"]),
            "trillionnium_owner_open_java_library":("java_library",["exclude_srcs","static_libs","required"])}
        for name,(parent,properties) in definitions.items():
            kind,props=sdk[name]
            expected=dict(name=name,module_type=parent,config_namespace="trillionnium_owner_open",
                bool_variables=["enabled"],properties=properties)
            if kind!="soong_config_module_type" or not typed_equal(props,expected):
                raise ValueError("owner selector declaration differs: "+name)
        types={"org.trillionnium.platform-res":"trillionnium_owner_open_android_app",
               "org.trillionnium.platform":"trillionnium_owner_open_java_library"}
        for name,expected in SEALED_MODULE_PROPERTIES.items():
            kind,props=sdk[name]
            if kind!=types[name] or not typed_equal(project(props,False),expected):
                raise ValueError("sealed default selected module properties differ: "+name)
        if not typed_equal(sdk["trillionnium-sdk-defaults"],("java_defaults",SDK_DEFAULT_PROPERTIES)):
            raise ValueError("ordinary/public SDK default source or HAL dependency inputs differ")
        platform=sdk["org.trillionnium.platform"][1]
        branch=platform["soong_config_variables"]["enabled"]
        default={"static_libs":["trillionnium-agent-identity-product","trillionnium-capability-lease-binder-api"],
                 "required":["org.trillionnium.agent.system_api.xml"]}
        if not typed_equal(branch,{"exclude_srcs":OWNER_EXCLUDES,"conditions_default":default}):
            raise ValueError("owner precise source exclusion or sealed dependency branch differs")
        selected=project(platform,True)
        if selected.get("required") or selected.get("static_libs"):
            raise ValueError("owner retains sealed feature/static dependencies")
        res=sdk["org.trillionnium.platform-res"][1]
        expected_res={"enabled":{"resource_dirs":["trillionnium/res/res","owner-open/res"],
            "conditions_default":{"resource_dirs":["trillionnium/res/res"]}}}
        if not typed_equal(res["soong_config_variables"],expected_res):
            raise ValueError("owner base/overlay resource order or sealed resource selection differs")
        xml=ET.fromstring(read(root,OWNER_XML))
        if xml.tag!="resources" or len(xml)!=1:
            raise ValueError("owner override must contain only the service array")
        array=xml[0]
        if array.tag!="string-array" or array.attrib!={"name":"config_externalTrillionniumServices"}:
            raise ValueError("owner service array declaration differs")
        if any(n.tag!="item" or n.attrib or len(n) for n in array) or [(n.text or "").strip() for n in array]!=OWNER_SERVICES:
            raise ValueError("owner ordinary service selection differs")
        owner_product_bool(read(root,PRODUCT))
        facts.update(owner_source_exclusion_globs=OWNER_EXCLUDES,owner_platform_services=OWNER_SERVICES,
            sealed_default_selected_module_properties_match_contract=True,
            owner_old_static_and_feature_edges_absent=True,ordinary_sdk_defaults_match_contract=True,
            owner_bool_unconditional_restricted_product_statement_verified=True,
            full_kati_inherited_product_export_qualified=False)
        return {"ok":True,"errors":[],"facts":facts}
    except (OSError,ValueError,KeyError,TypeError,IndexError,UnicodeError,ET.ParseError) as error:
        return {"ok":False,"errors":[str(error)],"facts":facts}

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root",type=Path,default=Path(__file__).resolve().parents[1])
    parser.add_argument("--json",action="store_true")
    args=parser.parse_args(argv);result=verify(args.root)
    if args.json:print(json.dumps(result,sort_keys=True))
    elif result["ok"]:print("Owner-open SDK source selector verification passed (not Soong qualification).")
    else:print("\n".join(result["errors"]),file=sys.stderr)
    return 0 if result["ok"] else 1

if __name__=="__main__":raise SystemExit(main())
