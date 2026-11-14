package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Pure checks of current Moto Notes observations, never a save API or a goal oracle.
 * The caller supplies actual observation/installed facts and binds task, native run,
 * dispatch, freshness and display continuity separately. No text is normalized.
 */
public final class NotesCompletionEvidence {
    public static final String NOTES="com.motorola.stylus";
    public static final String OBSERVED_BASE_APK_SHA256=
            "0e1a52a937c04ec8df380bff3750ce4b345fa0d8d33683e5ae8aa08e70e94017";
    public static final String PERSISTENCE_LIMIT=
            "Observed text only; trailing LF origin and persistent storage bytes are unverified.";
    public static final String LIST_TEXT_SCOPE=
            "Complete accessibility text source; visual clipping and persistent storage bytes are unverified.";
    private static final String FORTY_LF=fortyLf();
    private static final int MAX_NODES=200;
    private NotesCompletionEvidence() {}

    public static final class Frame {
        public final String observationId,packageName,backgroundGeneration;
        public final int windowId,displayId,windowType;
        public final boolean metadataObserved,nodesTruncated;
        public final List<Node> nodes;
        public Frame(String observationId,String packageName,int windowId,int displayId,
                     String backgroundGeneration,int windowType,boolean metadataObserved,
                     boolean nodesTruncated,List<Node> nodes){
            this.observationId=observationId;this.packageName=packageName;this.windowId=windowId;
            this.displayId=displayId;this.backgroundGeneration=backgroundGeneration;
            this.windowType=windowType;this.metadataObserved=metadataObserved;this.nodesTruncated=nodesTruncated;
            this.nodes=nodes==null?null:Collections.unmodifiableList(new ArrayList<Node>(nodes));
        }
    }
    public static final class Node {
        public final String id,packageName,text,label,viewId,inputTextSha256;
        public final int left,top,right,bottom;
        public final boolean editable,clickable,scrollable,enabled,password;
        public final ObservedChildText.Result childText;
        public final String observedAppTreeSignature;
        /** Same-traversal metadata; legacy callers leave these unknown. */
        public final String className,nativeTreePath;
        private final boolean boundsKnown;
        /** label is the complete original display label, before the existing 36-unit projection.
         * For unavailable/truncated derived child text the bridge must supply an empty label. */
        public Node(String id,String packageName,String text,String label,String viewId,String inputTextSha256,
                    int[] bounds,boolean editable,boolean clickable,boolean scrollable,boolean enabled,boolean password){
            this(id,packageName,text,label,viewId,inputTextSha256,bounds,editable,clickable,scrollable,enabled,password,ObservedChildText.notApplicable(),null);
        }
        public Node(String id,String packageName,String text,String label,String viewId,String inputTextSha256,
                    int[] bounds,boolean editable,boolean clickable,boolean scrollable,boolean enabled,boolean password,
                    ObservedChildText.Result childText,String observedAppTreeSignature){
            this(id,packageName,text,label,viewId,inputTextSha256,bounds,editable,clickable,scrollable,enabled,password,
                    childText,observedAppTreeSignature,null,null);
        }
        public Node(String id,String packageName,String text,String label,String viewId,String inputTextSha256,
                    int[] bounds,boolean editable,boolean clickable,boolean scrollable,boolean enabled,boolean password,
                    ObservedChildText.Result childText,String observedAppTreeSignature,String className,String nativeTreePath){
            this.id=id;this.packageName=packageName;this.text=text;this.label=label;this.viewId=viewId;
            this.inputTextSha256=inputTextSha256;boundsKnown=bounds!=null&&bounds.length==4;
            left=boundsKnown?bounds[0]:0;top=boundsKnown?bounds[1]:0;
            right=boundsKnown?bounds[2]:0;bottom=boundsKnown?bounds[3]:0;
            this.editable=editable;this.clickable=clickable;this.scrollable=scrollable;
            this.enabled=enabled;this.password=password;
            this.childText=childText==null?ObservedChildText.notApplicable():childText;this.observedAppTreeSignature=observedAppTreeSignature;
            this.className=className;this.nativeTreePath=nativeTreePath;
        }
        public int[] bounds(){return new int[]{left,top,right,bottom};}
    }
    public static final class Installed {
        public final String packageName;
        public final int uid;
        /** Actual sourceDir hash under "base", and actual split hashes under "split:" + split name. */
        public final Map<String,String> apkHashes;
        public Installed(String packageName,int uid,Map<String,String> apkHashes){
            this.packageName=packageName;this.uid=uid;
            this.apkHashes=apkHashes==null?null:Collections.unmodifiableMap(new LinkedHashMap<String,String>(apkHashes));
        }
    }
    public static final class BodyEvidence {
        public final boolean matched,rawExact,persistentBytesVerified;
        public final String nodeId,actionLabel,rawTextSha256,bodySha256,matchRule,missing;
        public final int trailingLfCount;
        private BodyEvidence(boolean matched,boolean rawExact,Node node,String rawSha,String bodySha,
                             int trailingLfCount,String rule,String missing){
            this.matched=matched;this.rawExact=rawExact;persistentBytesVerified=false;
            nodeId=node==null?null:node.id;
            actionLabel=node==null?null:ObservedTargetLabels.project(node.label);
            rawTextSha256=rawSha;bodySha256=bodySha;this.trailingLfCount=trailingLfCount;
            matchRule=rule;this.missing=missing;
        }
    }
    public static final class Item {
        public final String nodeId,label,fullLabel,text;
        public final int left,top,right,bottom;
        private Item(Node node){
            nodeId=node.id;fullLabel=node.label;label=ObservedTargetLabels.project(node.label);text=node.text;
            left=node.left;top=node.top;right=node.right;bottom=node.bottom;
        }
        public int[] bounds(){return new int[]{left,top,right,bottom};}
    }
    public static final class ListEvidence {
        public final boolean matched;
        public final String missing;
        public final Item item;
        public final String matchRule,sourcePath,sourceViewId,sourceTextSha256,observedAppTreeSignature;
        private ListEvidence(String missing,Node node){
            this(missing,node,null,null);
        }
        private ListEvidence(String missing,Node node,String rule,ObservedChildText.Source source){
            this.missing=missing;matched=missing==null&&node!=null;item=matched?new Item(node):null;
            matchRule=rule;sourcePath=source==null?null:source.descendantPath;sourceViewId=source==null?null:source.viewId;
            sourceTextSha256=source==null?null:source.textSha256;observedAppTreeSignature=node==null?null:node.observedAppTreeSignature;
        }
        public Map<String,Object> evidence(){
            Map<String,Object> o=new LinkedHashMap<String,Object>();o.put("matched",matched);o.put("missing",missing);o.put("match_rule",matchRule);
            o.put("node_id",item==null?null:item.nodeId);o.put("source_path",sourcePath);o.put("source_view_id",sourceViewId);
            o.put("source_text_sha256",sourceTextSha256);o.put("node_app_tree_sha256",observedAppTreeSignature);o.put("text_scope",LIST_TEXT_SCOPE);
            o.put("persistent_bytes_verified",false);return o;
        }
    }

    public static BodyEvidence editor(Frame frame,String body,Installed installed){
        String error=frameError(frame);
        if(error!=null)return absentBody(error,body);
        if(!validBody(body))return absentBody("nonempty_valid_owner_body_required",body);
        if(!installedValid(installed))return absentBody("actual_installed_notes_identity_required",body);
        Node context=null,editor=null;int contexts=0,editors=0;
        for(Node node:frame.nodes){
            if(!NOTES.equals(node.packageName)||!node.enabled||node.password)continue;
            if(!node.editable&&"NoteEditor".equals(node.text)&&node.scrollable&&validBounds(node)){
                context=node;contexts++;
            }
            if(node.editable){editor=node;editors++;}
        }
        // A full-height Moto editor may fit without advertising a scroll action.
        // Keep the old scrollable path intact. The additional path requires the
        // actual WebView class and traversal ancestry; the label alone is not proof.
        boolean nonScrollableContext=false;
        if(contexts==0){
            Node candidate=null;int labelled=0;
            for(Node node:frame.nodes){
                if(NOTES.equals(node.packageName)&&node.enabled&&!node.password&&!node.editable
                        &&"NoteEditor".equals(node.text)){candidate=node;labelled++;}
            }
            if(labelled==1&&!candidate.scrollable&&validBounds(candidate)
                    &&"android.webkit.WebView".equals(candidate.className)
                    &&nativePath(candidate.nativeTreePath)&&isSha(candidate.observedAppTreeSignature)){
                context=candidate;contexts=1;nonScrollableContext=true;
            }
        }
        if(contexts!=1)return absentBody("unique_observed_NoteEditor_context_required",body);
        if(editors!=1)return absentBody("unique_enabled_nonpassword_editable_required",body);
        if(!validBounds(editor)||!inside(editor,context))return absentBody("editable_outside_observed_editor_bounds",body);
        if(nonScrollableContext&&!observedEditorDescendant(frame.nodes,context,editor))
            return absentBody("non_scroll_editor_requires_actual_webview_ancestor",body);
        String rawSha=sha(editor.text),bodySha=sha(body);
        boolean rawExact=body.equals(editor.text);
        boolean observedForty=(body+FORTY_LF).equals(editor.text);
        int lfCount=trailingLf(editor.text);
        String rule=rawExact?"raw_exact":observedForty?"body_plus_observed_40_lf":"unsupported_raw_difference";
        if(!isSha(editor.inputTextSha256)||!rawSha.equals(editor.inputTextSha256))
            return new BodyEvidence(false,rawExact,editor,rawSha,bodySha,lfCount,rule,"complete_input_sha_does_not_match_observed_text");
        if(!rawExact&&!observedForty)
            return new BodyEvidence(false,false,editor,rawSha,bodySha,lfCount,rule,"observed_body_differs_from_supported_forms");
        if(observedForty&&!observedSingleBase(installed))
            return new BodyEvidence(false,false,editor,rawSha,bodySha,lfCount,rule,"forty_lf_form_requires_exact_observed_single_base_apk");
        return new BodyEvidence(true,rawExact,editor,rawSha,bodySha,lfCount,rule,null);
    }

    public static ListEvidence list(Frame frame,String body){
        String error=frameError(frame);
        if(error!=null)return absentList(error);
        if(!validBody(body))return absentList("nonempty_valid_owner_body_required");
        // Native node text is limited to 96 UTF-16 units; child labels may be shorter.
        // A shortened value must never impersonate an entire requested body.
        if(body.length()>=95)return absentList("body_too_long_to_prove_complete_list_item");
        if(body.endsWith("…"))return absentList("body_ending_ellipsis_cannot_prove_unshortened_list_item");
        Node title=null,pager=null;int titles=0,pagers=0;
        for(Node node:frame.nodes){
            if(node.editable||"NoteEditor".equals(node.text))return absentList("editor_present_not_note_list");
            if(!NOTES.equals(node.packageName))continue;
            if((NOTES+":id/no_note_text").equals(node.viewId)&&!node.text.isEmpty())return absentList("empty_list_notice_present");
            if((NOTES+":id/title_text").equals(node.viewId)&&"所有笔记".equals(node.text)
                    &&node.enabled&&!node.password&&validBounds(node)){title=node;titles++;}
            if((NOTES+":id/view_pager2").equals(node.viewId)&&node.scrollable
                    &&node.enabled&&!node.password&&validBounds(node)){pager=node;pagers++;}
        }
        if(titles!=1||pagers!=1)return absentList("unique_all_notes_title_and_scrollable_pager_required");
        Node item=null;int matches=0;String rule=null;ObservedChildText.Source matchedSource=null;
        for(Node node:frame.nodes){
            if(node==title||node==pager||!NOTES.equals(node.packageName)||!node.clickable
                    ||!node.enabled||node.password||!validBounds(node)||!inside(node,pager))continue;
            // The observed header click target is not a saved item, even if the owner
            // happens to request a note whose entire body is the title "所有笔记".
            if((NOTES+":id/clickable_layout").equals(node.viewId))continue;
            boolean ownText=body.equals(node.text)&&node.text.equals(node.label);
            // A derived label can never fall back to a title/date matching the
            // body. Its real summary source and parent binding are mandatory.
            boolean fullLabel=node.text.isEmpty()&&body.equals(node.label)&&!"derived".equals(node.childText.status);
            ObservedChildText.Source source=summarySource(node,body);
            if(ownText||fullLabel||source!=null){item=node;matches++;matchedSource=source;
                rule=source!=null?"bound_note_summary_accessibility_text":ownText?"exact_own_text":"exact_nonderived_label";}
        }
        if(matches==0)return absentList("complete_body_on_one_executable_list_item_missing");
        if(matches!=1)return absentList("complete_body_list_item_is_not_unique");
        // Bounds establish only list scope, never an inferred ancestor link.
        return new ListEvidence(null,item,rule,matchedSource);
    }

    private static ObservedChildText.Source summarySource(Node node,String body){
        ObservedChildText.Result child=node.childText;
        if(!(NOTES+":id/note_item_content").equals(node.viewId)||!node.text.isEmpty()
                ||!"derived".equals(child.status)||child.truncated||!child.sourcesComplete||!node.label.equals(child.text)
                ||child.text.isEmpty()||child.text.length()>ObservedChildText.MAX_CHARACTERS
                ||child.visited<1||child.visited>ObservedChildText.MAX_DESCENDANTS||child.sources.isEmpty()
                ||child.sources.size()>ObservedChildText.MAX_PARTS||!isSha(child.rootSignature)
                ||!isSha(node.observedAppTreeSignature)||!child.bind(child.rootSignature).equals(node.observedAppTreeSignature))return null;
        Set<String> paths=new HashSet<String>();ObservedChildText.Source summary=null;int summaries=0;
        for(ObservedChildText.Source source:child.sources){
            if(source==null||!sourcePath(source.descendantPath)||!paths.add(source.descendantPath)
                    ||!("text".equals(source.property)||"description".equals(source.property))
                    ||!isSha(source.textSha256)||!isSha(source.nodeSignature)||!unicode(source.viewId))return null;
            if((NOTES+":id/note_summary").equals(source.viewId)){
                summaries++;if("text".equals(source.property)&&sha(body).equals(source.textSha256))summary=source;
            }
        }
        return summaries==1?summary:null;
    }
    private static boolean sourcePath(String path){
        if(path==null||!path.matches("[0-9]{1,2}(?:/[0-9]{1,2}){0,3}"))return false;
        for(String part:path.split("/")){
            int index=Integer.parseInt(part);
            if(index>=ObservedChildText.MAX_DESCENDANTS||!Integer.toString(index).equals(part))return false;
        }
        return true;
    }

    private static String frameError(Frame frame){
        if(frame==null)return "actual_frame_required";
        if(!id(frame.observationId)||!NOTES.equals(frame.packageName))return "actual_notes_observation_identity_required";
        if(!frame.metadataObserved||frame.windowType!=1||frame.windowId<0)return "observed_application_window_metadata_required";
        if(frame.displayId<0||(frame.displayId==0?frame.backgroundGeneration!=null:!uuid(frame.backgroundGeneration)))
            return "display_and_background_generation_must_match";
        if(frame.nodesTruncated||frame.nodes==null||frame.nodes.size()>MAX_NODES)return "complete_bounded_observed_nodes_required";
        Set<String> ids=new HashSet<String>();
        for(Node node:frame.nodes){
            if(node==null||node.id==null||!node.id.matches("n[0-9]{1,5}")||!ids.add(node.id))
                return "unique_actual_node_ids_required";
            if(!unicode(node.text)||!unicode(node.label)||!unicode(node.viewId)||!unicode(node.packageName))
                return "valid_raw_node_strings_required";
        }
        return null;
    }
    private static boolean installedValid(Installed installed){
        if(installed==null||!NOTES.equals(installed.packageName)||installed.uid<10000||installed.uid>=90000
                ||installed.apkHashes==null||installed.apkHashes.isEmpty()||installed.apkHashes.size()>128
                ||!isSha(installed.apkHashes.get("base")))return false;
        for(Map.Entry<String,String> entry:installed.apkHashes.entrySet()){
            String key=entry.getKey();
            if(key==null||(!"base".equals(key)&&(!key.startsWith("split:")||key.length()==6))
                    ||key.length()>300||!unicode(key)||!isSha(entry.getValue()))return false;
        }
        return true;
    }
    private static boolean observedSingleBase(Installed installed){
        return installed.apkHashes.size()==1&&OBSERVED_BASE_APK_SHA256.equals(installed.apkHashes.get("base"));
    }
    private static boolean nativePath(String path){
        return path!=null&&path.matches("0(?:/(?:0|[1-9][0-9]{0,5})){0,127}");
    }
    private static boolean observedEditorDescendant(List<Node> nodes,Node context,Node editor){
        if(!"android.widget.EditText".equals(editor.className)||!nativePath(editor.nativeTreePath)
                ||!editor.nativeTreePath.startsWith(context.nativeTreePath+"/")
                ||!isSha(editor.observedAppTreeSignature))return false;
        for(Node node:nodes){
            if(node!=context&&context.nativeTreePath.equals(node.nativeTreePath))return false;
            if(node!=editor&&editor.nativeTreePath.equals(node.nativeTreePath))return false;
        }
        return true;
    }
    private static boolean validBounds(Node n){return n.boundsKnown&&n.left>=0&&n.top>=0&&n.right>n.left&&n.bottom>n.top;}
    private static boolean inside(Node n,Node outer){return outer.left<=n.left&&outer.top<=n.top&&n.right<=outer.right&&n.bottom<=outer.bottom;}
    private static boolean validBody(String body){return unicode(body)&&!body.isEmpty()&&body.indexOf('\0')<0;}
    private static boolean id(String value){return value!=null&&value.matches("[0-9a-f]{32}");}
    private static boolean isSha(String value){return value!=null&&value.matches("[0-9a-f]{64}");}
    private static boolean uuid(String value){return value!=null&&value.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");}
    private static boolean unicode(String value){
        if(value==null)return false;
        for(int i=0;i<value.length();i++){
            char c=value.charAt(i);
            if(Character.isHighSurrogate(c)){
                if(i+1>=value.length()||!Character.isLowSurrogate(value.charAt(++i)))return false;
            }else if(Character.isLowSurrogate(c))return false;
        }
        return true;
    }
    private static String sha(String value){
        try{
            byte[] bytes=MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            char[] hex=new char[64],alphabet="0123456789abcdef".toCharArray();
            for(int i=0;i<bytes.length;i++){hex[2*i]=alphabet[(bytes[i]&255)>>>4];hex[2*i+1]=alphabet[bytes[i]&15];}
            return new String(hex);
        }catch(NoSuchAlgorithmException impossible){throw new IllegalStateException(impossible);}
    }
    private static int trailingLf(String text){int n=0;for(int i=text.length()-1;i>=0&&text.charAt(i)=='\n';i--)n++;return n;}
    private static String fortyLf(){StringBuilder out=new StringBuilder(40);for(int i=0;i<40;i++)out.append('\n');return out.toString();}
    private static BodyEvidence absentBody(String missing,String body){
        return new BodyEvidence(false,false,null,null,validBody(body)?sha(body):null,-1,"unavailable",missing);
    }
    private static ListEvidence absentList(String missing){return new ListEvidence(missing,null);}
}
