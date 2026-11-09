import org.trillionnium.hepta.local.ActionDecision;
import org.trillionnium.hepta.local.AppCatalogueRanker;
import org.trillionnium.hepta.local.AppSearchProvenance;
import org.trillionnium.hepta.local.RecentActionProjection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/** Real page/provenance contracts; no model, Android or action dispatch. */
public final class AppSearchProvenanceHostTest {
    private static int assertions;
    private static void check(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
    private interface Invalid {void run()throws Exception;}
    private static void rejected(Invalid action,String why)throws Exception{
        boolean rejected=false;try{action.run();}catch(IllegalArgumentException expected){rejected=true;}
        check(rejected,why);
    }
    private static ActionDecision query(String query,int offset)throws Exception{
        return ActionDecision.parse("{\"action\":\"find_app\",\"observation_id\":\"11111111111111111111111111111111\","
                +"\"package\":\"com.example.launcher\",\"query\":\""+query+"\",\"offset\":"+offset+"}");
    }
    private static AppCatalogueRanker catalogue(){
        Map<String,String> installed=new LinkedHashMap<String,String>();
        for(int i=0;i<11;i++)installed.put("com.example.notes"+i,"便签 "+i);
        installed.put("com.example.clock","时钟");
        return new AppCatalogueRanker(installed,"先查询再打开所需应用");
    }
    public static void main(String[] ignored)throws Exception{
        final AppCatalogueRanker ranker=catalogue();
        final AppCatalogueRanker.Page initial=ranker.search("",0);
        Map<String,Object> initialFacts=AppSearchProvenance.initialRanking(initial).project(initial,2);
        check("initial_ranking".equals(initialFacts.get("source")),"initial ranking source is explicit");
        check(Boolean.FALSE.equals(initialFacts.get("model_issued")),"ranking is not model-issued");
        check(Boolean.FALSE.equals(initialFacts.get("tool_completed")),"tool completion specifically refers to find_app");
        check(initialFacts.containsKey("source_step")&&initialFacts.get("source_step")==null,"initial source has no model step");
        check(Integer.valueOf(2).equals(initialFacts.get("next_offset")),"partial page continues after shown entries");

        final ActionDecision first=query("便签",0);
        final AppCatalogueRanker.Page page=ranker.search(first.query,first.offset);
        final AppSearchProvenance provenance=AppSearchProvenance.completedFindApp(page,first,1,true,false);
        Map<String,Object> facts=provenance.project(page,2);
        check("model_find_app".equals(facts.get("source")),"completed source is a real model query");
        check(Boolean.TRUE.equals(facts.get("model_issued"))&&Boolean.TRUE.equals(facts.get("tool_completed")),"read-only completion preserved");
        check(Integer.valueOf(1).equals(facts.get("source_step")),"completion binds original step");
        check(page.catalogueSha256.equals(facts.get("catalogue_sha256")),"catalogue SHA is bound");
        check(first.query.equals(facts.get("query"))&&Integer.valueOf(first.offset).equals(facts.get("offset")),"query and offset are exact");
        check(Integer.valueOf(2).equals(facts.get("next_offset")),"budget truncation does not skip returned but unshown apps");
        check(Integer.valueOf(6).equals(provenance.project(page,6).get("next_offset")),"untruncated page resumes at page end");
        check(Integer.valueOf(0).equals(provenance.project(page,0).get("next_offset")),"zero shown entries are not a false terminal page");
        check(!facts.containsKey("dispatched"),"discovery provenance never asserts a dispatched effect");

        rejected(new Invalid(){public void run(){AppSearchProvenance.completedFindApp(page,first,1,false,false);}},"rejected receipt cannot complete query");
        rejected(new Invalid(){public void run(){AppSearchProvenance.completedFindApp(page,first,1,true,true);}},"dispatched receipt is inconsistent with read-only query");
        rejected(new Invalid(){public void run(){AppSearchProvenance.completedFindApp(page,first,0,true,false);}},"query requires a model step");
        rejected(new Invalid(){public void run(){AppSearchProvenance.completedFindApp(page,null,1,true,false);}},"null action rejected");
        rejected(new Invalid(){public void run()throws Exception{AppSearchProvenance.completedFindApp(page,query("时钟",0),1,true,false);}},"query mismatch rejected");
        rejected(new Invalid(){public void run()throws Exception{AppSearchProvenance.completedFindApp(page,query("便签",2),1,true,false);}},"offset mismatch rejected");
        rejected(new Invalid(){public void run(){provenance.project(ranker.search("便签",0),2);}},"equivalent later query needs its own completion");
        rejected(new Invalid(){public void run(){provenance.project(ranker.search("便签",2),2);}},"another page cannot inherit completion");
        rejected(new Invalid(){public void run(){provenance.project(ranker.search("时钟",0),1);}},"another query cannot inherit completion");
        rejected(new Invalid(){public void run(){provenance.project(catalogue().search("便签",0),2);}},"another snapshot cannot inherit completion");
        rejected(new Invalid(){public void run(){provenance.project(page,7);}},"invalid shown count rejects instead of forging pagination");
        boolean immutable=false;try{facts.put("tool_completed",false);}catch(UnsupportedOperationException expected){immutable=true;}
        check(immutable,"projected provenance cannot be mutated");

        for(int step=2;step<=20;step++){
            String term=(step%2==0)?"时钟":"便签";
            ActionDecision action=query(term,0);AppCatalogueRanker.Page next=ranker.search(term,0);
            AppSearchProvenance latest=AppSearchProvenance.completedFindApp(next,action,step,true,false);
            Map<String,Object> projected=latest.project(next,next.apps.size());
            check(projected.size()==facts.size(),"many queries retain one bounded fact");
            check(Integer.valueOf(step).equals(projected.get("source_step"))&&term.equals(projected.get("query")),"latest query replaces prior provenance");
            if("时钟".equals(term))check(projected.get("next_offset")==null,"terminal result remains terminal");
        }
        ActionDecision none=query("不存在的应用",0);AppCatalogueRanker.Page empty=ranker.search(none.query,0);
        Map<String,Object> missing=AppSearchProvenance.completedFindApp(empty,none,20,true,false).project(empty,0);
        check(Boolean.TRUE.equals(missing.get("tool_completed"))&&Integer.valueOf(0).equals(missing.get("matches")),"successful empty query is still completed");
        check(missing.get("next_offset")==null,"empty search cannot invent another page");
        Map<String,Object> readOnly=new LinkedHashMap<String,Object>();
        readOnly.put("step",1);readOnly.put("action","find_app");readOnly.put("query","便签");readOnly.put("offset",0);readOnly.put("dispatched",false);
        check(RecentActionProjection.compactDispatched(Collections.singletonList(readOnly),20).observed==0,"readonly fact is not forged into dispatched history");
        System.out.println("PASS "+assertions+" query provenance assertions; phone_tested=false");
    }
}
