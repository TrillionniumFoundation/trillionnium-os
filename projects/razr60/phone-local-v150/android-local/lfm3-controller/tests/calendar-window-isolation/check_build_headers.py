#!/usr/bin/env python3
"""Exercise the actual header build block and DEX definition guard, without D8/APK execution."""
import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import zipfile


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--java-home',type=Path,required=True);p.add_argument('--port-classes',type=Path,required=True)
    a=p.parse_args();source=a.source.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    raw=(source/'build_mac.py').read_text();tree=ast.parse(raw);rows=[];assertions=0;commands=[]
    def yes(value,why):
        nonlocal assertions
        assertions+=1
        if not value:raise AssertionError(why)
    def case(name,work):
        start=assertions
        work();rows.append({'name':name,'passed':True,'assertions':assertions-start})
    def reject(work,why):
        try:work()
        except RuntimeError:
            yes(True,why);return
        raise AssertionError('accepted: '+why)
    def run(argv):
        command=list(map(str,argv));r=subprocess.run(command,capture_output=True,timeout=60)
        (out/'compile-heads.stdout').write_bytes(r.stdout);(out/'compile-heads.stderr').write_bytes(r.stderr)
        commands.append({'argv':command,'exit_code':r.returncode})
        if r.returncode:raise RuntimeError('actual header block javac failed')
    def name_of(node):
        return node.targets[0].id if isinstance(node,ast.Assign) and isinstance(node.targets[0],ast.Name) else None
    begin=next(i for i,n in enumerate(tree.body) if name_of(n)=='HEADER_ROOT')
    end=next(i for i,n in enumerate(tree.body) if name_of(n)=='sources')
    g={'ROOT':source,'OUT':out,'JDK':a.java_home.resolve(),'ANDROID_JAR':a.port_classes.resolve(),
       'Path':Path,'os':os,'shutil':shutil,'zipfile':zipfile,'run':run}
    block=ast.Module(body=tree.body[begin:end],type_ignores=[])
    exec(compile(block,str(source/'build_mac.py'),'exec'),g)
    header_names=list(g['header_names']);head_classes=g['header_classes'];header_jar=g['header_jar']
    def isolated_headers():
        yes(sorted(x.relative_to(head_classes).as_posix() for x in head_classes.rglob('*') if x.is_file())==header_names,'exact three independently compiled classes')
        with zipfile.ZipFile(header_jar) as jar:
            yes(jar.namelist()==header_names,'isolated jar exact membership')
            for name in header_names:yes(jar.read(name)==(head_classes/name).read_bytes(),'jar exact class bytes')
        yes(not (out/'classes').exists() and not (out/'dex').exists(),'header block creates no app or DEX output')
    case('actual_header_build_block_compiles_exact_three_separate_classes',isolated_headers)
    identity_path=source/'tools/build_identity.py';spec=importlib.util.spec_from_file_location('calendar_build_identity',identity_path)
    identity=importlib.util.module_from_spec(spec);spec.loader.exec_module(identity)
    input_map=identity.source_inputs(source)
    def source_binding():
        selected=[x for x in input_map if x['path'].startswith('compile-only/')]
        yes([x['path'] for x in selected]==['compile-only/window-infos/android/view/InputWindowHandle.java','compile-only/window-infos/android/window/WindowInfosListener.java'],'two actual headers in source identity')
        for row in selected:yes(row['sha256']==hashlib.sha256((source/row['path']).read_bytes()).hexdigest(),'actual source header hash')
    case('actual_source_identity_binds_both_headers',source_binding)
    captured=[]
    cg=dict(g,run=lambda argv:captured.append(list(map(str,argv))),BT=out/'unexecuted-sdk-build-tools',
            sources=sorted((source/'src').rglob('*.java')),classes=[out/'classes/org/example/App.class'])
    command_nodes=[]
    for node in tree.body[end:]:
        text=ast.get_source_segment(raw,node) or ''
        if isinstance(node,ast.Expr) and isinstance(node.value,ast.Call) and isinstance(node.value.func,ast.Name) and node.value.func.id=='run' and ('OUT/\'classes\'' in text or 'com.android.tools.r8.D8' in text):
            command_nodes.append(node)
    def classpath_only():
        yes(len(command_nodes)==2,'exact app javac and D8 command expressions')
        exec(compile(ast.Module(body=command_nodes,type_ignores=[]),str(source/'build_mac.py'),'exec'),cg)
        javac,d8=captured
        yes(javac[javac.index('-classpath')+1]==os.pathsep.join((str(a.port_classes.resolve()),str(header_jar))),'app javac headers only classpath')
        yes(d8[d8.index('--classpath')+1]==str(header_jar),'D8 header jar only classpath')
        yes(d8[-1]==str(out/'classes/org/example/App.class') and d8.count(str(header_jar))==1,'D8 program input excludes header jar')
        yes(all('/compile-only/' not in x for x in javac[javac.index('-d')+2:]),'application source excludes compile-only heads')
    case('actual_app_and_D8_command_expressions_use_classpath_only',classpath_only)
    function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='declared_dex_classes')
    dex_guard=next(n for n in tree.body if isinstance(n,ast.If) and 'if not dex_files or any(' in (ast.get_source_segment(raw,n) or ''))
    forbidden={('L'+name[:-6]+';').encode('ascii') for name in header_names}
    dg={'struct':struct,'forbidden_headers':forbidden}
    exec(compile(ast.Module(body=[function],type_ignores=[]),str(source/'build_mac.py'),'exec'),dg)
    def fixture(classes):
        names=sorted(forbidden|{b'Lorg/example/App;'});count=len(names)
        strings_at=112;types_at=strings_at+4*count;classes_at=types_at+4*count;data_at=classes_at+32*len(classes)
        data=bytearray(data_at);data[:8]=b'dex\n035\0'
        for at,value in ((56,count),(60,strings_at),(64,count),(68,types_at),(96,len(classes)),(100,classes_at)):
            struct.pack_into('<I',data,at,value)
        for i,name in enumerate(names):
            struct.pack_into('<I',data,strings_at+i*4,len(data));struct.pack_into('<I',data,types_at+i*4,i)
            data.extend(bytes([len(name)])+name+b'\0')
        for i,name in enumerate(classes):struct.pack_into('<I',data,classes_at+i*32,names.index(name))
        return bytes(data)
    synthetic=out/'synthetic-class-table.dex'
    def check(data):
        synthetic.write_bytes(data);dg['dex_files']=[synthetic]
        exec(compile(ast.Module(body=[dex_guard],type_ignores=[]),str(source/'build_mac.py'),'exec'),dg)
    def legal_references():
        check(fixture([b'Lorg/example/App;']))
        yes(dg['declared_dex_classes'](synthetic)=={b'Lorg/example/App;'},'framework references are not definitions')
    case('actual_DEX_guard_allows_references_without_framework_definitions',legal_references)
    def forbidden_definitions():
        for name in sorted(forbidden):reject(lambda name=name:check(fixture([name])),'framework definition '+name.decode())
    case('actual_DEX_guard_rejects_each_compile_only_definition',forbidden_definitions)
    def malformed():
        reject(lambda:check(b'not a dex'),'non-DEX')
        data=bytearray(fixture([b'Lorg/example/App;']));struct.pack_into('<I',data,100,len(data))
        reject(lambda:check(bytes(data)),'truncated class table')
        dg['dex_files']=[]
        reject(lambda:exec(compile(ast.Module(body=[dex_guard],type_ignores=[]),str(source/'build_mac.py'),'exec'),dg),'missing D8 result')
    case('actual_DEX_guard_rejects_missing_or_malformed_class_tables',malformed)
    result={'schema':'hepta.calendar-compile-only-build-host.v1','all_pass':True,'cases':len(rows),'assertions':assertions,'rows':rows,
            'actual_header_compile_commands':commands,'actual_command_AST_evaluated_without_app_javac_or_D8':captured,
            'actual_header_classpath_is_host_android_port_classes':True,'header_classpath':str(a.port_classes.resolve()),
            'source_inputs':input_map,'actual_dex_guard_function_sha256':hashlib.sha256(ast.get_source_segment(raw,function).encode()).hexdigest(),
            'header_jar_sha256':hashlib.sha256(header_jar.read_bytes()).hexdigest(),'synthetic_DEX_table_only':True,
            'actual_SDK_compilation':False,'actual_D8_execution':False,'actual_app_DEX_or_APK':False,'phone_actions':0,'input_calls':0}
    (out/'RESULT.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print(json.dumps({'all_pass':True,'cases':len(rows),'assertions':assertions,'actual_D8_execution':False}))


if __name__=='__main__':main()
