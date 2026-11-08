package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Bounded labels from a clickable node's actual non-interactive descendant subtree. */
public final class ObservedChildText {
    public static final String SOURCE="visible_noninteractive_descendants.v1";
    public static final int MAX_DESCENDANTS=16, MAX_DEPTH=4, MAX_PARTS=3, MAX_CHARACTERS=96;
    private ObservedChildText() {}
    public static final class Metadata {
        public final boolean visible,inScope,clickable,clickAction,inputLike,password,interactive;
        public Metadata(boolean visible,boolean inScope,boolean clickable,boolean clickAction,
                        boolean inputLike,boolean password,boolean interactive){
            this.visible=visible;this.inScope=inScope;this.clickable=clickable;this.clickAction=clickAction;
            this.inputLike=inputLike;this.password=password;this.interactive=interactive;
        }
    }
    /** Root is borrowed; each non-null child returned by child() is released once. */
    public interface Reader<T> {
        Metadata metadata(T node);
        String text(T node);
        String description(T node);
        String identity(T node);
        int childCount(T node);
        T child(T node,int index);
        void release(T node);
    }
    public static final class Source {
        public final String descendantPath,property,textSha256,nodeSignature;
        Source(String path,String property,String text,String identity){
            descendantPath=path;this.property=property;textSha256=hash(text);nodeSignature=identity;
        }
        String fingerprint(){return field(descendantPath)+field(property)+field(textSha256)+field(nodeSignature);}
    }
    public static final class Result {
        public final String text,status,fingerprint;
        public final boolean truncated;
        public final int visited;
        public final List<Source> sources;
        Result(String text,String status,boolean truncated,int visited,List<Source> sources){
            this.text=text;this.status=status;this.truncated=truncated;this.visited=visited;
            this.sources=Collections.unmodifiableList(new ArrayList<Source>(sources));
            StringBuilder value=new StringBuilder(field(SOURCE)+field(status)+field(text)+field(Boolean.toString(truncated)));
            for(Source source:sources)value.append(source.fingerprint());fingerprint=hash(value.toString());
        }
        /** The original node signature remains part of target and whole-graph identity. */
        public String bind(String originalNodeSignature){return hash(field(originalNodeSignature)+field(fingerprint));}
    }
    private static final class Pending<T> {
        final T node;final String path;final int depth;
        Pending(T node,String path,int depth){this.node=node;this.path=path;this.depth=depth;}
    }
    private static final class Budget {int acquired;boolean truncated;}
    private static Result none(String status){return new Result("",status,false,0,Collections.<Source>emptyList());}
    public static Result notApplicable(){return none("not_applicable");}
    public static String displayLabel(String text,String description,Result childText){
        if(!string(text).trim().isEmpty())return text;
        if(!string(description).trim().isEmpty())return description;
        return childText.text;
    }
    public static <T> Result collect(T root,Reader<T> reader){
        ArrayDeque<Pending<T>> pending=new ArrayDeque<Pending<T>>();
        List<Source> sources=new ArrayList<Source>();Set<String> seen=new HashSet<String>();
        StringBuilder label=new StringBuilder();Budget budget=new Budget();int visited=0;
        try{
            Metadata owner=reader.metadata(root);
            // Input/password bodies are not requested, even for a clickable root.
            if(owner==null||!owner.visible||!owner.inScope||!owner.clickable||!owner.clickAction||owner.inputLike||owner.password)
                return notApplicable();
            if(!string(reader.text(root)).trim().isEmpty()||!string(reader.description(root)).trim().isEmpty())return notApplicable();
            enqueue(root,"",0,reader,pending,budget);
            while(!pending.isEmpty()){
                Pending<T> current=pending.removeFirst();visited++;
                try{
                    Metadata node=reader.metadata(current.node);
                    if(node==null)throw new IllegalStateException("descendant metadata unavailable");
                    // These are whole-subtree boundaries; do not borrow another control's label/body.
                    if(!node.visible||!node.inScope||node.inputLike||node.password||node.clickable||node.clickAction||node.interactive)continue;
                    String raw=string(reader.text(current.node)),property="text";
                    if(raw.trim().isEmpty()){raw=string(reader.description(current.node));property="description";}
                    String value=raw.trim();
                    if(!value.isEmpty()&&seen.add(value)){
                        String separator=label.length()==0?"":" · ";int available=MAX_CHARACTERS-label.length()-separator.length();
                        if(available<=0||sources.size()>=MAX_PARTS){budget.truncated=true;break;}
                        String part=limited(value,available);label.append(separator).append(part);
                        sources.add(new Source(current.path,property,raw,reader.identity(current.node)));
                        if(part.length()<value.length())budget.truncated=true;
                    }
                    if(label.length()>=MAX_CHARACTERS||sources.size()>=MAX_PARTS){
                        if(!pending.isEmpty()||reader.childCount(current.node)>0)budget.truncated=true;
                        break;
                    }
                    enqueue(current.node,current.path,current.depth,reader,pending,budget);
                }finally{reader.release(current.node);}
            }
            return new Result(label.toString(),label.length()==0?"empty":"derived",budget.truncated,visited,sources);
        }catch(RuntimeException unavailable){
            // Stale/inaccessible children do not produce a partially asserted label.
            return none("unavailable");
        }finally{while(!pending.isEmpty()){try{reader.release(pending.removeFirst().node);}catch(RuntimeException ignored){/* best-effort reference cleanup */}}}
    }
    private static <T> void enqueue(T parent,String path,int depth,Reader<T> reader,
                                   ArrayDeque<Pending<T>> pending,Budget budget){
        int children=reader.childCount(parent);if(children<0)throw new IllegalStateException("invalid child count");
        if(depth>=MAX_DEPTH){if(children>0)budget.truncated=true;return;}
        int admitted=Math.min(children,MAX_DESCENDANTS-budget.acquired);
        if(admitted<children)budget.truncated=true;
        for(int i=0;i<admitted;i++){
            T child=reader.child(parent,i);if(child==null)throw new IllegalStateException("descendant disappeared");
            budget.acquired++;pending.addLast(new Pending<T>(child,path.isEmpty()?Integer.toString(i):path+"/"+i,depth+1));
        }
    }
    private static String limited(String text,int maximum){
        if(text.length()<=maximum)return text;
        int end=Math.max(0,maximum-1);if(end>0&&Character.isHighSurrogate(text.charAt(end-1)))end--;
        return text.substring(0,end)+"…";
    }
    private static String string(String value){return value==null?"":value;}
    private static String field(String value){String safe=string(value);return safe.length()+":"+safe;}
    private static String hash(String value){
        try{byte[] digest=MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));StringBuilder hex=new StringBuilder(64);
            for(byte b:digest)hex.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return hex.toString();
        }catch(java.security.NoSuchAlgorithmException impossible){throw new IllegalStateException(impossible);}
    }
}
