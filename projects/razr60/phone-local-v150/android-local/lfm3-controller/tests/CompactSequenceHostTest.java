import org.trillionnium.hepta.local.RecentActionProjection;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class CompactSequenceHostTest {
    private static Map<String,Object> row(Object... values) {
        Map<String,Object> result=new LinkedHashMap<String,Object>();
        for(int i=0;i<values.length;i+=2)result.put((String)values[i],values[i+1]);
        return result;
    }
    private static void require(boolean value,String message) {
        if(!value)throw new AssertionError(message);
    }
    private static Object packageAt(RecentActionProjection.CompactSequence sequence,int row,int column) {
        Object index=sequence.rows.get(row).get(column);
        require(index instanceof Integer,"present package must reference dictionary");
        return sequence.packages.get(((Integer)index).intValue());
    }
    private static Map<?,?> details(RecentActionProjection.CompactSequence sequence,int row) {
        return (Map<?,?>)sequence.rows.get(row).get(5);
    }
    private static void actualNavigationOrder() {
        List<Map<String,Object>> input=new ArrayList<Map<String,Object>>();
        input.add(row("step",2,"action","open","target_package","example.target","before_package","example.launcher","package_after","example.related","dispatched",true));
        input.add(row("step",3,"action","home","target_package","example.related","before_package","example.related","package_after","example.launcher","dispatched",true));
        input.add(row("step",4,"action","open","target_package","example.target","before_package","example.launcher","package_after","example.target","dispatched",true));
        RecentActionProjection.CompactSequence s=RecentActionProjection.compactDispatched(input,20);
        require(s.observed==3&&s.omitted==0&&s.rows.size()==3,"complete observed order lost");
        require(s.rows.get(0).get(0).equals(2)&&s.rows.get(1).get(1).equals("home")&&s.rows.get(2).get(0).equals(4),"steps/actions reordered");
        require(packageAt(s,0,2).equals("example.target")&&packageAt(s,0,4).equals("example.related"),"actual after package replaced with requested target");
        require(packageAt(s,1,3).equals("example.related")&&packageAt(s,1,4).equals("example.launcher"),"home before/after guessed");
        require(packageAt(s,2,3).equals("example.launcher")&&packageAt(s,2,4).equals("example.target"),"observed return path lost");
        require(RecentActionProjection.SEQUENCE_COLUMNS.equals(Arrays.asList("step","action","target_package","before_package","after_package","details")),"column contract changed");
    }
    private static void onlyConfirmedDispatchesAndSuffix() {
        List<Map<String,Object>> input=new ArrayList<Map<String,Object>>();
        input.add(row("step",1,"action","click","target_package","example.old","before_package","example.old","package_after","example.old","dispatched",true));
        input.add(row("step",2,"action","find_app","query","target","read_only",true,"dispatched",false));
        input.add(row("step",3,"action_rejected","stale observation","dispatched",false));
        input.add(row("step",4,"action","open","dispatched","true"));
        input.add(row("step",5,"action","back","target_package","example.current","before_package","example.current","package_after","example.parent","dispatched",true));
        RecentActionProjection.CompactSequence s=RecentActionProjection.compactDispatched(input,1);
        require(s.observed==2&&s.omitted==1&&s.rows.size()==1,"read-only/rejected/missing true became effect");
        require(s.rows.get(0).get(0).equals(5),"retained prefix instead of actual suffix");
        require(!s.packages.contains("example.old"),"omitted-only package leaked into dictionary");
        s=RecentActionProjection.compactDispatched(input,0);
        require(s.observed==2&&s.omitted==2&&s.rows.isEmpty()&&s.packages.isEmpty(),"zero budget omission wrong");
    }
    private static void missingNullEmptyAndOriginalUnchanged() {
        Map<String,Object> source=row("step",1,"action","home","target_package","","package_after",null,"dispatched",true);
        Map<String,Object> original=new LinkedHashMap<String,Object>(source);
        List<Map<String,Object>> input=new ArrayList<Map<String,Object>>();input.add(source);
        RecentActionProjection.CompactSequence s=RecentActionProjection.compactDispatched(input,1);
        require(packageAt(s,0,2).equals(""),"empty actual package value fabricated");
        require(s.rows.get(0).get(3)==null,"missing before column not null");
        require(details(s,0).get("absent_columns").equals(Arrays.asList(3)),"missing before column not explicit");
        require(packageAt(s,0,4)==null,"explicit null after package lost");
        require(!((List<?>)details(s,0).get("absent_columns")).contains(4),"explicit null treated as absent");
        require(source.equals(original),"private raw history mutated");
        require(!details(s,0).containsKey("node_label")&&!details(s,0).containsKey("type_text"),"missing details invented");
    }
    private static void detailsAndUnicodeBound() {
        StringBuilder text=new StringBuilder();for(int i=0;i<79;i++)text.append('x');text.append("\ud83d\ude00z");
        List<Map<String,Object>> input=new ArrayList<Map<String,Object>>();
        input.add(row("step",5,"action","type","target_package","example.app","before_package","example.app","package_after","example.app",
                "node_label","","type_text",text.toString(),"dispatched",true));
        input.add(row("step",6,"action","scroll","target_package","example.app","before_package","example.app","package_after","example.app",
                "node_label","Observed list","direction","forward","dispatched",true));
        RecentActionProjection.CompactSequence s=RecentActionProjection.compactDispatched(input,2);
        require(s.packages.size()==1,"same observed package repeated in dictionary");
        require("".equals(details(s,0).get("node_label")),"empty actual label lost");
        require(Boolean.TRUE.equals(details(s,0).get("type_text_truncated"))&&details(s,0).get("type_text").equals(text.substring(0,79)+"…"),"type excerpt/surrogate contract changed");
        require("forward".equals(details(s,1).get("direction")),"observed scroll direction lost");
        require(!details(s,1).containsKey("type_text"),"irrelevant type text fabricated");
    }
    private static void longRepeatedPackageHistoryAndImmutability() {
        List<Map<String,Object>> input=new ArrayList<Map<String,Object>>();
        for(int i=0;i<20;i++)input.add(row("step",i+1,"action","click","target_package","example.same","before_package","example.same",
                "package_after","example.same","node_label","Observed "+i,"dispatched",true));
        RecentActionProjection.CompactSequence s=RecentActionProjection.compactDispatched(input,20);
        require(s.rows.size()==20&&s.packages.equals(Arrays.<Object>asList("example.same")),"long trajectory lost or packages not deduplicated");
        require(s.rows.equals(RecentActionProjection.compactDispatched(input,20).rows),"projection nondeterministic");
        for(int i=0;i<20;i++)require(s.rows.get(i).get(0).equals(i+1)&&details(s,i).get("node_label").equals("Observed "+i),"actual ordered label changed");
        try{s.packages.add("changed");throw new AssertionError("dictionary mutable");}catch(UnsupportedOperationException expected){}
        try{s.rows.get(0).set(0,99);throw new AssertionError("row mutable");}catch(UnsupportedOperationException expected){}
        try{s.rows.clear();throw new AssertionError("row collection mutable");}catch(UnsupportedOperationException expected){}
    }
    private static void rejectsInvalidInputs() {
        try{RecentActionProjection.compactDispatched(null,1);throw new AssertionError("null history admitted");}catch(IllegalArgumentException expected){}
        try{RecentActionProjection.compactDispatched(new ArrayList<Map<String,Object>>(),-1);throw new AssertionError("negative limit admitted");}catch(IllegalArgumentException expected){}
        List<Map<String,Object>> input=new ArrayList<Map<String,Object>>();input.add(null);
        try{RecentActionProjection.compactDispatched(input,1);throw new AssertionError("null source row admitted");}catch(IllegalArgumentException expected){}
    }
    public static void main(String[] args) {
        actualNavigationOrder();onlyConfirmedDispatchesAndSuffix();missingNullEmptyAndOriginalUnchanged();
        detailsAndUnicodeBound();longRepeatedPackageHistoryAndImmutability();rejectsInvalidInputs();
        System.out.println("6 compact factual sequence contracts passed");
    }
}
