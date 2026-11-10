import org.trillionnium.hepta.local.ObservedChildText;
import org.trillionnium.hepta.local.ObservationState;
import org.trillionnium.hepta.local.ImeVisibility;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Runs the real bounded traversal/label/freshness code against explicit tree observations. */
public final class ObservedChildTextHostTest {
    private static int assertions;
    private static final class Node {
        String text="",description="",identity="node";
        boolean visible=true,inScope=true,clickable,clickAction,input,password,interactive,forbidText,missing;
        int fetched,released,textReads,childReads;
        final List<Node> children=new ArrayList<Node>();
        Node child(Node... values){children.addAll(Arrays.asList(values));return this;}
    }
    private static final class Reader implements ObservedChildText.Reader<Node> {
        int acquired,released;
        public ObservedChildText.Metadata metadata(Node n){return new ObservedChildText.Metadata(n.visible,n.inScope,n.clickable,n.clickAction,n.input,n.password,n.interactive);}
        private void readable(Node n){if(n.forbidText)throw new AssertionError("protected/boundary text was read");n.textReads++;}
        public String text(Node n){readable(n);return n.text;}
        public String description(Node n){readable(n);return n.description;}
        public String identity(Node n){return n.identity;}
        public int childCount(Node n){n.childReads++;return n.children.size();}
        public Node child(Node n,int i){Node child=n.children.get(i);if(child.missing)return null;child.fetched++;acquired++;return child;}
        public void release(Node n){n.released++;released++;}
    }
    private static Node label(String text){Node n=new Node();n.text=text;return n;}
    private static Node button(){Node n=new Node();n.clickable=true;n.clickAction=true;n.interactive=true;return n;}
    private static void check(boolean valid,String description){assertions++;if(!valid)throw new AssertionError(description);}
    private static ObservedChildText.Result collect(Node root){Reader reader=new Reader();ObservedChildText.Result result=ObservedChildText.collect(root,reader);
        check(reader.acquired==reader.released,"all fetched descendant references released");check(root.released==0,"root remains borrowed");return result;}
    private static String repeat(String value,int count){StringBuilder b=new StringBuilder();for(int i=0;i<count;i++)b.append(value);return b.toString();}
    public static void main(String[] args){
        Node apps=button().child(new Node().child(label("应用")));
        ObservedChildText.Result observed=collect(apps);
        check("应用".equals(observed.text),"empty Apps container gets actual nested label");
        check("0/0".equals(observed.sources.get(0).descendantPath),"relative subtree provenance");
        check("text".equals(observed.sources.get(0).property),"source property is explicit");
        check("应用".equals(ObservedChildText.displayLabel("","",observed)),"prompt fallback uses parent label");

        // Actual code8 failure shape: clickable empty popup parent [624,154,1212,298]
        // and non-clickable visible label child [672,194,1164,258]. Android adapter
        // checks same window/package and intersecting bounds before setting inScope.
        Node clearHistory=button().child(label("清除历史记录"));
        ObservedChildText.Result destructive=collect(clearHistory);
        check("清除历史记录".equals(destructive.text),"popup parent cannot remain anonymous");
        check("清除历史记录".equals(ObservedChildText.displayLabel("","",destructive)),"destructive label reaches prompt fallback");
        check(!destructive.bind("same-parent-signature").equals(observed.bind("same-parent-signature")),"different actual descendants change parent signature");

        Node input=label("NFC 私人输入");input.input=true;input.forbidText=true;input.child(label("不应读取"));
        Node search=button().child(input);
        check(collect(search).text.isEmpty(),"search parent must not inherit input body/hint");
        check(input.textReads==0&&input.childReads==0,"input subtree is not read or traversed");
        Node searchLabel=label("搜索设置");search.child(searchLabel);
        check("搜索设置".equals(collect(search).text),"separate non-input static search label may be used");

        for(int boundary=0;boundary<6;boundary++){
            Node nested=label("删除记录");nested.forbidText=true;nested.child(label("更深的秘密"));
            if(boundary==0)nested.clickable=true;if(boundary==1)nested.clickAction=true;
            if(boundary==2)nested.interactive=true;if(boundary==3)nested.password=true;
            if(boundary==4)nested.visible=false;if(boundary==5)nested.inScope=false;
            check(collect(button().child(nested)).text.isEmpty(),"nested interaction/password/scope boundary "+boundary);
            check(nested.textReads==0&&nested.childReads==0,"boundary is never read or traversed "+boundary);
        }
        Node password=button();password.password=true;password.forbidText=true;password.child(label("隐私"));
        check("not_applicable".equals(collect(password).status),"password root excluded before text");
        Node editable=button();editable.input=true;editable.forbidText=true;
        check("not_applicable".equals(collect(editable).status),"input root excluded before text");
        Node noClick=button();noClick.clickAction=false;noClick.forbidText=true;
        check("not_applicable".equals(collect(noClick).status),"clickable flag alone does not supply ACTION_CLICK");
        Node own=button();own.text="父自身名称";own.child(label("子名称"));
        check("not_applicable".equals(collect(own).status)&&own.childReads==0,"own text has priority");
        check("父自身名称".equals(ObservedChildText.displayLabel("父自身名称","描述",observed)),"own-text precedence");
        check("描述".equals(ObservedChildText.displayLabel("","描述",observed)),"own-description precedence");

        Node description=new Node();description.description="实际图标描述";
        ObservedChildText.Result described=collect(button().child(description));
        check("description".equals(described.sources.get(0).property),"description fallback has accurate source");
        Node multiple=button().child(label("名称"),label("名称"),label("副标题"));
        check("名称 · 副标题".equals(collect(multiple).text),"duplicate labels do not consume parts");
        Node tooMany=button().child(label("一"),label("二"),label("三"),label("四"));
        ObservedChildText.Result capped=collect(tooMany);
        check(capped.sources.size()==ObservedChildText.MAX_PARTS&&capped.truncated,"source part cap is explicit");
        Node longLabel=button().child(label(repeat("😀",100)));
        ObservedChildText.Result clipped=collect(longLabel);
        check(clipped.text.length()<=ObservedChildText.MAX_CHARACTERS&&clipped.truncated,"bounded label characters");
        for(int i=0;i<clipped.text.length();i++)if(Character.isHighSurrogate(clipped.text.charAt(i)))check(++i<clipped.text.length()&&Character.isLowSurrogate(clipped.text.charAt(i)),"surrogate pair remains intact");

        Node broad=button();for(int i=0;i<40;i++)broad.child(new Node());
        Reader boundedReader=new Reader();ObservedChildText.Result bounded=ObservedChildText.collect(broad,boundedReader);
        check(boundedReader.acquired==ObservedChildText.MAX_DESCENDANTS&&boundedReader.released==boundedReader.acquired&&bounded.truncated,"descendant budget and cleanup");
        Node deep=button(),cursor=deep;for(int i=0;i<8;i++){Node child=new Node();cursor.child(child);cursor=child;}cursor.text="过深文本";
        ObservedChildText.Result depth=collect(deep);check(depth.text.isEmpty()&&depth.truncated&&depth.visited==ObservedChildText.MAX_DEPTH,"depth bound");
        Node gone=label("消失");gone.missing=true;
        ObservedChildText.Result unavailable=collect(button().child(label("部分文本"),gone));
        check("unavailable".equals(unavailable.status)&&unavailable.text.isEmpty()&&unavailable.sources.isEmpty(),"missing child drops partial asserted label");

        String before=destructive.bind("same-parent-signature");clearHistory.children.get(0).text="取消";
        ObservedChildText.Result changed=collect(clearHistory);String after=changed.bind("same-parent-signature");
        check(!before.equals(after),"label-only change invalidates target signature");
        ObservationState first=new ObservationState(before,ImeVisibility.HIDDEN),second=new ObservationState(after,ImeVisibility.HIDDEN);
        check(Boolean.TRUE.equals(second.changedFrom(first)),"label binding participates in graph progress/freshness");
        check(!changed.bind("parent-A").equals(changed.bind("parent-B")),"original parent signature remains bound");
        Node changedSource=button().child(label("取消"));changedSource.children.get(0).identity="different-source-node";
        check(!changed.fingerprint.equals(collect(changedSource).fingerprint),"source identity change also invalidates label binding");
        System.out.println("ObservedChildTextHostTest: "+assertions+" assertions passed");
    }
}
