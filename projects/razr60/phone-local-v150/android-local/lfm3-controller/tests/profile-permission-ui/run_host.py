#!/usr/bin/env python3
"""Execute the production permission UI worker with explicit inert Android/RPC substitutes.

This is a concurrency/lifecycle check, not Android adapter or phone qualification.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time

STUBS = {
    'android/os/Looper.java': '''package android.os;
public final class Looper {
 private static final Looper MAIN=new Looper();private static volatile Thread main;
 public static void initializeMain(){if(main!=null&&main!=Thread.currentThread())throw new IllegalStateException();main=Thread.currentThread();}
 public static Looper getMainLooper(){return MAIN;}
 public static Looper myLooper(){return Thread.currentThread()==main?MAIN:null;}
}''',
    'android/os/Handler.java': '''package android.os;
public final class Handler {public Handler(Looper ignored){}public boolean post(Runnable callback){return true;}}
''',
    'android/os/SystemClock.java': '''package android.os;
public final class SystemClock {private static final long BEGIN=System.nanoTime();public static long elapsedRealtime(){return 1000+(System.nanoTime()-BEGIN)/1000000;}}
''',
    'org/json/JSONException.java': '''package org.json;
public final class JSONException extends Exception {public JSONException(String message){super(message);}}
''',
    'org/json/JSONObject.java': '''package org.json;
public final class JSONObject {
 public static final Object NULL=new Object();private final java.util.Map<String,Object> values=new java.util.LinkedHashMap<String,Object>();
 public JSONObject(){}public JSONObject(java.util.Map<?,?> map){for(java.util.Map.Entry<?,?> e:map.entrySet())values.put(String.valueOf(e.getKey()),e.getValue());}
 public JSONObject put(String key,Object value)throws JSONException{if(key==null)throw new JSONException("key");values.put(key,value);return this;}
 public boolean getBoolean(String key)throws JSONException{Object v=values.get(key);if(!(v instanceof Boolean))throw new JSONException(key);return ((Boolean)v).booleanValue();}
 private static String quote(String text){StringBuilder b=new StringBuilder("\\\"");for(int i=0;i<text.length();i++){char c=text.charAt(i);if(c=='\\\\'||c=='\\\"')b.append('\\\\');if(c=='\\n')b.append("\\\\n");else if(c=='\\r')b.append("\\\\r");else b.append(c);}return b.append('\\\"').toString();}
 private static String encode(Object value){if(value==null||value==NULL)return "null";if(value instanceof String)return quote((String)value);if(value instanceof Boolean||value instanceof Number)return value.toString();if(value instanceof java.util.Map){StringBuilder b=new StringBuilder("{");for(Object o:((java.util.Map<?,?>)value).entrySet()){java.util.Map.Entry<?,?> e=(java.util.Map.Entry<?,?>)o;if(b.length()>1)b.append(',');b.append(quote(String.valueOf(e.getKey()))).append(':').append(encode(e.getValue()));}return b.append('}').toString();}if(value instanceof Iterable){StringBuilder b=new StringBuilder("[");for(Object o:(Iterable<?>)value){if(b.length()>1)b.append(',');b.append(encode(o));}return b.append(']').toString();}return quote(value.toString());}
 public String toString(){return encode(values);}public String toString(int ignored)throws JSONException{return toString();}
}''',
}

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    classes = output/'classes'
    classes.mkdir()
    stubs = output/'stubs'
    generated = []
    for name, content in STUBS.items():
        path = stubs/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content+'\n')
        generated.append(path)
    names = ['ProfileIdentity','ProfileTarget','WindowOwnership','BrokerProtocol','PublicPermissionControllerUi','PublicOwnGroupPolicy','FixedIntentTools',
             'BackgroundOwnedTaskPolicy','BackgroundOwnedSingleTask','ProfileTaskPolicy','ProfileOwnedTask',
             'ProfilePermissionTransient','ProfileDisplayCustody','PermissionWindowObservation']
    background = source/'src/org/trillionnium/hepta/background'
    inputs = [background/(name+'.java') for name in names]
    inputs += [source/'src/org/trillionnium/hepta/local'/name for name in
               ['NativeAppGoal.java','ProfilePermissionInitialization.java','ProfilePermissionUiSession.java']]
    inputs += [source/'tests/profile-broker/ProfileBrokerHostTest.java',
               source/'tests/profile-permission-transient/ProfilePermissionTransientHostTest.java']
    inputs += [source/'tests/profile-permission-ui'/name for name in
               ['UiPermissionFixture.java','UiLifecycleFakes.java','ProfilePermissionUiLifecycleHostTest.java']]
    fixture=source/'tests/profile-permission-transient/fixtures/synthetic-activities.txt'
    pins={str(path):sha(path) for path in inputs+generated+[fixture,Path(__file__).resolve()]}
    result={'schema':'hepta.permission-ui-host.v1','all_pass':False,'base_head':'f7dbe2f1c06e34c992b140d5d88995a8e99c03db','source_head_from_ci':None,
            'java_release_api_check':True,'compiler_contract':'Java 8 API release; no fallback from --release 8',
            'production_ui_session_executed':False,'android_adapters_compiled':False,'phone_contacted':False,'apk_built':False,
            'substitutes':['Android Looper/Handler/SystemClock/JSON','Hepta service and scope identity','BackgroundSession RPC',
                           'ProfilePermissionAndroidAdapter A11y','MobiMindPrivateFiles uses host CREATE_NEW+force'],
            'handler_callbacks_rendered':False,'fixtures_synthetic':True,'source_inputs_sha256':pins,'stages':[]}
    def run(name,argv):
        start=time.monotonic()
        process=subprocess.run(argv,capture_output=True,timeout=50)
        (output/(name+'.stdout')).write_bytes(process.stdout)
        (output/(name+'.stderr')).write_bytes(process.stderr)
        result['stages'].append({'name':name,'exit_code':process.returncode,'elapsed_seconds':time.monotonic()-start})
        if process.returncode:
            raise RuntimeError(name+' failed; inspect original stdout/stderr')
        return process.stdout.decode()
    try:
        java=args.java_home.resolve()/'bin/java';javac=args.java_home.resolve()/'bin/javac'
        if not java.is_file() or not javac.is_file():
            raise RuntimeError('Existing full JDK required; no fallback')
        if sha(fixture)!='7f8adcb158486f74a1ebe342e54902b9fc7550ed7b0dd7bf11b36d1d97ab63f0':
            raise RuntimeError('synthetic fixture changed')
        run('compile',[str(javac),'--release','8','-encoding','UTF-8','-d',str(classes)]
            +[str(path) for path in inputs+generated])
        output_text=run('ui-lifecycle',[str(java),'-cp',str(classes),'org.trillionnium.hepta.local.ProfilePermissionUiLifecycleHostTest',str(fixture)])
        result['checks']=json.loads(output_text.rstrip().splitlines()[-1])
        result['production_ui_session_executed']=True
        for path,digest in pins.items():
            if sha(Path(path))!=digest:
                raise RuntimeError('source changed during tests: '+path)
        result['source_inputs_unchanged']=True
        result['all_pass']=True
    except Exception as error:
        result['error']=str(error)
    finally:
        (output/'RESULT.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'all_pass':result['all_pass'],'checks':result.get('checks'),'result':str(output/'RESULT.json'),'error':result.get('error')}))
    return 0 if result['all_pass'] else 1

if __name__=='__main__':
    raise SystemExit(main())
