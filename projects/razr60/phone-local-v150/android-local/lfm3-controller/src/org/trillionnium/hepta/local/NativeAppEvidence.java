package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/** Detached facts from one actual bounded native observation. Nothing in this
 * type supplies a node reference, dispatch permission, query or completion.
 * The Android adapter is the only production creator of these values.
 */
final class NativeAppEvidence {
    static final String SCHEMA="hepta.native-app-observation.v1";
    static final int MAX_NODES=512;
    private NativeAppEvidence() {}

    static final class Installed {
        final String packageName,apkSetSha256;
        final int uid;
        final long versionCode;
        final Map<String,String> apkHashes;
        Installed(String pkg,int uid,long version,Map<String,String> hashes){
            need(pkg!=null&&uid>=10000&&uid<90000&&version>0&&hashes!=null&&!hashes.isEmpty(),"ordinary installed App identity required");
            TreeMap<String,String> copy=new TreeMap<String,String>();
            for(Map.Entry<String,String> e:hashes.entrySet()){
                need(e.getKey()!=null&&(e.getKey().equals("base")||e.getKey().matches("split:[A-Za-z0-9_.-]+"))&&sha(e.getValue()),"complete APK identity required");
                copy.put(e.getKey(),e.getValue());
            }
            need(copy.containsKey("base"),"base APK missing");packageName=pkg;this.uid=uid;versionCode=version;
            apkHashes=Collections.unmodifiableMap(copy);StringBuilder rows=new StringBuilder();
            for(Map.Entry<String,String> e:copy.entrySet())rows.append(e.getKey()).append('\t').append(e.getValue()).append('\n');
            apkSetSha256=hash(rows.toString());
        }
        Map<String,Object> evidence(){
            Map<String,Object> o=map();o.put("package",packageName);o.put("uid",uid);o.put("version_code",versionCode);
            o.put("apk_hashes",apkHashes);o.put("apk_set_sha256",apkSetSha256);return o;
        }
    }

    static final class Node {
        final String id,packageName,className,viewId,text,description,path,parentClass,signature,label;
        final int left,top,right,bottom;
        final boolean enabled,password,clickable,editable,scrollable;
        final Boolean selected,checkable,checked;
        final Set<String> scrollDirections;
        Node(String id,String pkg,String cls,String vid,String text,String desc,String path,String parent,
                String signature,String label,int left,int top,int right,int bottom,boolean enabled,boolean password,
                boolean clickable,boolean editable,boolean scrollable,Boolean selected,Boolean checkable,Boolean checked,
                Set<String> directions){
            need(id!=null&&id.matches("n[0-9]{1,4}")&&pkg!=null&&cls!=null&&vid!=null&&text!=null&&desc!=null&&label!=null,"actual node fields required");
            need(path==null||path.matches("0(?:/(?:0|[1-9][0-9]{0,5})){0,127}"),"actual node path malformed");
            need(path==null?parent==null:parent!=null&&parent.length()<=96,"native parent/path binding required");
            need(signature==null||sha(signature),"actual NodeRef signature malformed");
            need((selected==null&&checkable==null&&checked==null)||(selected!=null&&checkable!=null&&checked!=null),"partial native selection tuple");
            TreeSet<String> dirs=new TreeSet<String>();
            if(directions!=null)for(String d:directions){need(d!=null&&java.util.Arrays.asList("up","down","left","right","forward","backward").contains(d),"unknown actual scroll direction");dirs.add(d);}
            this.id=id;packageName=pkg;className=cls;viewId=vid;this.text=text;description=desc;this.path=path;parentClass=parent;
            this.signature=signature;this.label=label;this.left=left;this.top=top;this.right=right;this.bottom=bottom;
            this.enabled=enabled;this.password=password;this.clickable=clickable;this.editable=editable;this.scrollable=scrollable;
            this.selected=selected;this.checkable=checkable;this.checked=checked;scrollDirections=Collections.unmodifiableSet(dirs);
        }
        boolean direct(){return path!=null&&sha(signature)&&right>left&&bottom>top&&!password;}
        boolean within(Node parent){return direct()&&parent!=null&&parent.direct()&&path.startsWith(parent.path+"/")
                &&left>=parent.left&&top>=parent.top&&right<=parent.right&&bottom<=parent.bottom;}
        Map<String,Object> fact(String property){
            String raw="text".equals(property)?text:"description".equals(property)?description:null;
            need(raw!=null,"only exact observed text properties are facts");
            Map<String,Object> o=map();o.put("node_id",id);o.put("package",packageName);o.put("class_name",className);
            o.put("view_id",viewId);o.put("native_tree_path",path);o.put("native_parent_class",parentClass);o.put("node_ref_signature",signature);
            o.put("bounds",java.util.Arrays.asList(left,top,right,bottom));o.put("property",property);o.put("raw",raw);o.put("raw_utf8_sha256",hash(raw));
            o.put("selected",selected);o.put("checkable",checkable);o.put("checked",checked);o.put("selection_observed",selected!=null);
            o.put("source","same_bounded_native_observation");return o;
        }
    }

    static final class Frame {
        final String taskId,ownerSha,targetSha,authorizationSha,selectionSha,observationId,packageName,generation;
        final String treeSha,stateSha,screenshotSha,sourceRecordSha,completionFrameSha;
        final int displayId,windowId,rotation,width,height,left,top,right,bottom,windowType;
        final long capturedElapsedMs;
        final boolean nodesTruncated,collectionComplete,metadataObserved;
        final List<Node> nodes;
        final Map<String,Node> byId;
        Frame(String task,String owner,String target,String auth,String selection,String observation,String pkg,String generation,
                String tree,String state,String screen,String source,String completion,int display,int window,int rotation,
                int width,int height,int left,int top,int right,int bottom,long captured,boolean truncated,
                boolean countersComplete,List<Node> nodes){
            this(task,owner,target,auth,selection,observation,pkg,generation,tree,state,screen,source,completion,
                    display,window,rotation,width,height,left,top,right,bottom,captured,truncated,countersComplete,nodes,-1,false);
        }
        Frame(String task,String owner,String target,String auth,String selection,String observation,String pkg,String generation,
                String tree,String state,String screen,String source,String completion,int display,int window,int rotation,
                int width,int height,int left,int top,int right,int bottom,long captured,boolean truncated,
                boolean countersComplete,List<Node> nodes,int windowType,boolean metadataObserved){
            need(id(task)&&sha(owner)&&sha(target)&&sha(auth)&&sha(selection)&&id(observation)&&pkg!=null&&backgroundGeneration(generation),"native task/frame identities required");
            need(sha(tree)&&sha(state)&&sha(screen)&&sha(source)&&sha(completion),"native original frame hashes required");
            need(display>0&&window>=0&&rotation>=0&&rotation<=3&&width>0&&height>0&&right>left&&bottom>top&&captured>=0,"actual background window required");
            need(nodes!=null&&nodes.size()<=MAX_NODES,"bounded retained native graph required");
            Map<String,Node> ids=new LinkedHashMap<String,Node>();Set<String> paths=new TreeSet<String>();
            for(Node n:nodes){need(n!=null&&!ids.containsKey(n.id),"duplicate actual node id");ids.put(n.id,n);
                if(n.path!=null)need(paths.add(n.path),"duplicate actual native path");}
            taskId=task;ownerSha=owner;targetSha=target;authorizationSha=auth;selectionSha=selection;observationId=observation;packageName=pkg;
            this.generation=generation;treeSha=tree;stateSha=state;screenshotSha=screen;sourceRecordSha=source;completionFrameSha=completion;
            displayId=display;windowId=window;this.rotation=rotation;this.width=width;this.height=height;this.left=left;this.top=top;this.right=right;this.bottom=bottom;
            capturedElapsedMs=captured;nodesTruncated=truncated;collectionComplete=countersComplete&&!truncated;
            this.windowType=windowType;this.metadataObserved=metadataObserved;
            this.nodes=Collections.unmodifiableList(new ArrayList<Node>(nodes));byId=Collections.unmodifiableMap(ids);
        }
        boolean usable(Node n){return n!=null&&n.direct()&&packageName.equals(n.packageName)&&n.left>=left&&n.top>=top&&n.right<=right&&n.bottom<=bottom;}
        boolean sameSource(Frame f){return f!=null&&taskId.equals(f.taskId)&&ownerSha.equals(f.ownerSha)&&targetSha.equals(f.targetSha)
                &&authorizationSha.equals(f.authorizationSha)&&selectionSha.equals(f.selectionSha)&&observationId.equals(f.observationId)
                &&packageName.equals(f.packageName)&&generation.equals(f.generation)&&displayId==f.displayId&&windowId==f.windowId
                &&rotation==f.rotation&&treeSha.equals(f.treeSha)&&stateSha.equals(f.stateSha)&&sourceRecordSha.equals(f.sourceRecordSha)
                &&windowType==f.windowType&&metadataObserved==f.metadataObserved
                &&completionFrameSha.equals(f.completionFrameSha)&&screenshotSha.equals(f.screenshotSha);}
        Map<String,Object> evidence(){
            Map<String,Object> o=map();o.put("schema",SCHEMA);o.put("task_id",taskId);o.put("owner_sha256",ownerSha);o.put("execution_target_sha256",targetSha);
            o.put("task_authorization_sha256",authorizationSha);o.put("actual_selection_sha256",selectionSha);o.put("observation_id",observationId);
            o.put("package",packageName);o.put("background_generation",generation);o.put("display_id",displayId);o.put("window_id",windowId);o.put("rotation",rotation);
            o.put("window_type",metadataObserved?Integer.valueOf(windowType):null);o.put("window_metadata_observed",metadataObserved);
            o.put("app_tree_sha256",treeSha);o.put("observation_state_sha256",stateSha);o.put("screen_sha256",screenshotSha);
            o.put("phone_observation_record_sha256",sourceRecordSha);o.put("completion_frame_sha256",completionFrameSha);o.put("captured_elapsed_ms",capturedElapsedMs);
            o.put("retained_nodes",nodes.size());o.put("nodes_truncated",nodesTruncated);o.put("actual_collection_complete",collectionComplete);
            o.put("screenshots_used_as_text",false);return o;
        }
    }

    static Map<String,Object> map(){return new LinkedHashMap<String,Object>();}
    static Map<String,Object> immutableMap(Map<String,Object> source){
        Map<String,Object> out=map();for(Map.Entry<String,Object> e:source.entrySet())out.put(e.getKey(),immutableValue(e.getValue(),0));
        return Collections.unmodifiableMap(out);
    }
    private static Object immutableValue(Object value,int depth){
        need(depth<=16,"immutable evidence nesting budget");
        if(value==null||value instanceof String||value instanceof Boolean||value instanceof Byte||value instanceof Short||value instanceof Integer||value instanceof Long)return value;
        if(value instanceof Map<?,?>){Map<String,Object> out=map();for(Map.Entry<?,?> e:((Map<?,?>)value).entrySet()){
            need(e.getKey() instanceof String,"immutable evidence key");out.put((String)e.getKey(),immutableValue(e.getValue(),depth+1));}return Collections.unmodifiableMap(out);}
        if(value instanceof Iterable<?>){List<Object> out=new ArrayList<Object>();for(Object item:(Iterable<?>)value)out.add(immutableValue(item,depth+1));return Collections.unmodifiableList(out);}
        throw new IllegalArgumentException("immutable native evidence scalar type");
    }
    static boolean id(String v){return v!=null&&v.matches("[0-9a-f]{32}");}
    static boolean backgroundGeneration(String v){return v!=null&&v.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");}
    static boolean sha(String v){return v!=null&&v.matches("[0-9a-f]{64}");}
    static void need(boolean yes,String why){if(!yes)throw new IllegalArgumentException("native App evidence: "+why);}
    static String hash(String value){
        try{byte[] bytes=MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));StringBuilder out=new StringBuilder(64);
            char[] h="0123456789abcdef".toCharArray();for(byte b:bytes)out.append(h[(b>>>4)&15]).append(h[b&15]);return out.toString();
        }catch(NoSuchAlgorithmException impossible){throw new IllegalStateException(impossible);}
    }
    static String fingerprint(Object value){StringBuilder out=new StringBuilder();canonical(out,value,0);return hash(out.toString());}
    private static void canonical(StringBuilder out,Object value,int depth){
        need(depth<=16,"evidence nesting budget");
        if(value==null){out.append('n');return;}
        if(value instanceof String){String s=(String)value;out.append('s').append(s.getBytes(StandardCharsets.UTF_8).length).append(':').append(s);return;}
        if(value instanceof Boolean){out.append(Boolean.TRUE.equals(value)?'t':'f');return;}
        if(value instanceof Byte||value instanceof Short||value instanceof Integer||value instanceof Long){out.append('i').append(value).append(';');return;}
        if(value instanceof Map<?,?>){TreeMap<String,Object> sorted=new TreeMap<String,Object>();for(Map.Entry<?,?> e:((Map<?,?>)value).entrySet()){
            need(e.getKey() instanceof String,"evidence map key");sorted.put((String)e.getKey(),e.getValue());}
            out.append('{');for(Map.Entry<String,Object> e:sorted.entrySet()){canonical(out,e.getKey(),depth+1);canonical(out,e.getValue(),depth+1);}out.append('}');return;}
        if(value instanceof Iterable<?>){out.append('[');for(Object x:(Iterable<?>)value)canonical(out,x,depth+1);out.append(']');return;}
        throw new IllegalArgumentException("native evidence scalar type: "+Objects.toString(value.getClass()));
    }
}
