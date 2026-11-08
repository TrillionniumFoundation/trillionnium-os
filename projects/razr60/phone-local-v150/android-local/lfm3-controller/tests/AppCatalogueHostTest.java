import org.trillionnium.hepta.local.ActionDecision;
import org.trillionnium.hepta.local.ActionPolicy;
import org.trillionnium.hepta.local.AppCatalogueRanker;
import org.trillionnium.hepta.local.DecisionGrammar;
import org.trillionnium.hepta.local.ObservedTargetLabels;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Real parser/policy/catalogue/grammar contracts; no Android, model or app launch. */
public final class AppCatalogueHostTest {
    private static final String OBS = "f91c685bf5f04f5c9a6a3197eade1fed";
    private static final String CURRENT = "com.example.launcher";
    private static final String TARGET = "com.example.calculator";
    private static int assertions;

    public static void main(String[] args) throws Exception {
        Path grammarOut = Paths.get(args[0]); Files.createDirectories(grammarOut);
        ranking(); searchAndPaging(); boundsAndSnapshot(); discoveryToOpen(grammarOut);
        System.out.println("{\"schema\":\"hepta.app-discovery-host-tests.v1\",\"all_pass\":true,"
                + "\"assertions\":" + assertions + ",\"android_compiled\":false,\"phone_tested\":false,"
                + "\"native_grammar_tested\":false,\"external_model_used\":false}");
    }

    private static Map<String,String> fixture() {
        Map<String,String> apps = new LinkedHashMap<String,String>();
        for (int i=0; i<55; i++) apps.put(String.format(Locale.ROOT,"com.example.app%02d",i),"Tool " + i);
        apps.put(TARGET,"Calculator");
        apps.put("com.example.notes","Notes\t  Pad");
        apps.put("com.example.cafe","Café");
        apps.put("com.example.chinese","中文便签");
        return apps;
    }

    private static void ranking() {
        Map<String,String> apps = fixture();
        AppCatalogueRanker ranked = new AppCatalogueRanker(apps,"先看 Tool 0，再打开 com.example.calculator");
        check(first(ranked.search("",0)).equals(TARGET),"explicit installed package wins over a label mention");
        check(first(new AppCatalogueRanker(apps,"打开 calculator").search("",0)).equals(TARGET),"label matching ignores case");
        check(first(new AppCatalogueRanker(apps,"请打开 ＮＯＴＥＳ\u00a0ＰＡＤ").search("",0)).equals("com.example.notes"),"label matching normalizes width and whitespace");
        check(first(new AppCatalogueRanker(apps,"请打开 Cafe\u0301").search("",0)).equals("com.example.cafe"),"label matching normalizes decomposed accents");
        check(first(new AppCatalogueRanker(apps,"请打开中文便签").search("",0)).equals("com.example.chinese"),"Chinese exact label is prioritized");
        Map<String,String> packageBoundary=new LinkedHashMap<String,String>(apps);packageBoundary.put(TARGET,"Math Utility");
        for (String owner : new String[]{"open com.example.calculator.extra", "open xcom.example.calculator", "nothing matches"})
            check(first(new AppCatalogueRanker(packageBoundary,owner).search("",0)).equals("com.example.app00"),"a partial package token cannot receive exact-package priority");
        List<String> keys = new ArrayList<String>(apps.keySet()); Collections.reverse(keys);
        Map<String,String> reversed = new LinkedHashMap<String,String>(); for(String key:keys)reversed.put(key,apps.get(key));
        AppCatalogueRanker a = new AppCatalogueRanker(apps,"none"), b = new AppCatalogueRanker(reversed,"none");
        check(new ArrayList<String>(names(a.search("",0))).equals(new ArrayList<String>(names(b.search("",0)))),"unmatched alphabetical order is independent of source iteration");
        check(a.catalogueSha256.equals(b.catalogueSha256),"snapshot digest is deterministic");
        check(a.catalogueSha256.equals(ranked.catalogueSha256),"ranking does not rewrite observed catalogue identity");
    }

    private static void searchAndPaging() {
        AppCatalogueRanker ranker = new AppCatalogueRanker(fixture(),"打开计算器");
        AppCatalogueRanker.Page initial = ranker.search("",0);
        check(initial.totalApps==59 && initial.matchingApps==59,"all installed launcher entries survive the old 40-entry cutoff");
        check(initial.apps.size()==6&&!names(initial).contains(TARGET),"fixture reproduces target omitted from initial six");
        check(first(ranker.search("CALCUL",0)).equals(TARGET),"English package fragment discovers target despite Chinese owner wording");
        check(first(ranker.search("  notes \n pad  ",0)).equals("com.example.notes"),"search normalizes query whitespace");
        check(first(ranker.search("中文",0)).equals("com.example.chinese"),"Unicode substring search is local");
        check(ranker.search("com.unknown.notinstalled",0).apps.isEmpty(),"search cannot invent a missing installed package");
        check(ranker.search("am start; curl example.com",0).apps.isEmpty(),"query remains literal data, never a command");
        check(initial.nextOffset(1)==1,"budget projection advances only one shown app");
        check(first(ranker.search("",1)).equals(initial.apps.get(1).packageName),"budget-omitted row is reachable on the next page");
        Set<String> seen = new HashSet<String>(); int offset=0, rounds=0;
        do {
            AppCatalogueRanker.Page page = ranker.search("",offset);
            int shown=Math.min(2,page.apps.size());
            for(int i=0;i<shown;i++)check(seen.add(page.apps.get(i).packageName),"bounded pagination does not repeat entries");
            offset=page.nextOffset(shown); rounds++;
        } while(offset>=0&&rounds<100);
        check(offset==-1&&seen.size()==59&&seen.contains(TARGET),"every retained installed app is recoverable after prompt truncation");
        check(ranker.search("calculator",1).apps.isEmpty()&&ranker.search("calculator",1).nextOffset(0)==-1,"past-end queries are explicitly empty");
        check(ranker.search("",4095).apps.isEmpty(),"legal large offset remains bounded");
    }

    private static void boundsAndSnapshot() {
        Map<String,String> apps=fixture();
        AppCatalogueRanker ranker=new AppCatalogueRanker(apps,"owner");
        String identity=ranker.catalogueSha256;
        apps.clear();apps.put("com.evil.injected","Injected");
        check(ranker.search("",0).totalApps==59&&ranker.search("injected",0).apps.isEmpty(),"snapshot is independent of later map changes");
        check(identity.equals(ranker.catalogueSha256),"search leaves snapshot identity unchanged");
        boolean immutable=false;try{ranker.search("",0).apps.clear();}catch(UnsupportedOperationException expected){immutable=true;}
        check(immutable,"search results cannot mutate the snapshot");
        for(String query:new String[]{null,repeat("x",65),repeat("😀",65),"\0","\ud800","\udc00"}) {
            boolean rejected=false;try{ranker.search(query,0);}catch(IllegalArgumentException expected){rejected=true;}
            check(rejected,"query size/Unicode bounds are enforced outside the JSON parser too");
        }
        check(ranker.search(repeat("😀",64),0).apps.isEmpty(),"64 Unicode scalar values are allowed");
        for(int offset:new int[]{-1,4096,Integer.MAX_VALUE}) {
            boolean rejected=false;try{ranker.search("",offset);}catch(IllegalArgumentException expected){rejected=true;}
            check(rejected,"search offset bound");
        }
        boolean rejected=false;try{ranker.search("",0).nextOffset(7);}catch(IllegalArgumentException expected){rejected=true;}
        check(rejected,"paging cannot claim more rows than actually returned");
        Map<String,String> invalid=new LinkedHashMap<String,String>();invalid.put("com.example\"inject","App");
        rejected=false;try{new AppCatalogueRanker(invalid,"owner");}catch(IllegalArgumentException expected){rejected=true;}
        check(rejected,"untrusted package cannot inject an open grammar");
        Map<String,String> maximum=new LinkedHashMap<String,String>();
        for(int i=0;i<4096;i++)maximum.put("com.example.app"+i,"App "+i);
        AppCatalogueRanker large=new AppCatalogueRanker(maximum,"owner");
        check(large.search("",4095).apps.size()==1&&large.search("",4095).nextOffset(1)==-1,"largest admitted snapshot remains pageable");
        maximum.put("com.example.extra","Extra");
        rejected=false;try{new AppCatalogueRanker(maximum,"owner");}catch(IllegalArgumentException expected){rejected=true;}
        check(rejected,"oversized snapshot fails explicitly instead of silently hiding installed apps");
    }

    private static void discoveryToOpen(Path grammarOut) throws Exception {
        AppCatalogueRanker ranker=new AppCatalogueRanker(fixture(),"打开计算器");
        Set<String> initial=names(ranker.search("",0)),nodes=Collections.emptySet();
        ActionDecision open=ActionDecision.parse(json("open",TARGET,""));
        check(!allowed(open,initial,nodes),"unseen installed app cannot be opened before discovery");
        DecisionGrammar before=DecisionGrammar.create(OBS,CURRENT,initial,nodes,nodes,nodes,labels(nodes));
        Files.write(grammarOut.resolve("discovery-before.gbnf"),before.text.getBytes(StandardCharsets.UTF_8));
        String raw=json("find_app",CURRENT,",\"query\":\"calculator\",\"offset\":0");
        ActionDecision modelSearch=ActionDecision.parse(raw);
        check(allowed(modelSearch,initial,nodes)&&ActionPolicy.isReadOnlyDiscovery(modelSearch),"real parsed model search is authorized as a read-only tool");
        AppCatalogueRanker.Page found=ranker.search(modelSearch.query,modelSearch.offset);
        Set<String> supplied=names(found);
        check(found.apps.size()==1&&allowed(open,supplied,nodes),"only later open receives permission from supplied installed search results");
        check(!allowed(ActionDecision.parse(json("open","com.evil.injected","")),supplied,nodes),"search does not grant arbitrary package launch");
        check(!allowed(ActionDecision.parse(json("find_app",TARGET,",\"query\":\"calculator\",\"offset\":0")),initial,nodes),"search package still binds current observed screen");
        AppCatalogueRanker.Page more=ranker.search("",6);
        Set<String> one=Collections.singleton(more.apps.get(0).packageName);
        check(!allowed(ActionDecision.parse(json("open",more.apps.get(1).packageName,"")),one,nodes),"returned but prompt-omitted apps remain unauthorized");
        DecisionGrammar after=DecisionGrammar.create(OBS,CURRENT,supplied,nodes,nodes,nodes,labels(nodes));
        Files.write(grammarOut.resolve("discovery-after.gbnf"),after.text.getBytes(StandardCharsets.UTF_8));
        check(!before.sha256.equals(after.sha256),"discovered package produces a distinct bound grammar");
    }

    private static boolean allowed(ActionDecision action,Set<String> apps,Set<String> nodes) throws Exception {
        try{ActionPolicy.validateTextDecision(action,CURRENT,apps,labels(nodes));return true;}
        catch(ActionDecision.InvalidActionException denied){return false;}
    }
    private static ObservedTargetLabels labels(Set<String> nodes){
        Map<String,String> values=new LinkedHashMap<String,String>();for(String node:nodes)values.put(node,"");
        return ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,OBS,CURRENT,values);
    }
    private static String json(String action,String pkg,String fields){return "{\"action\":\""+action+"\",\"observation_id\":\""+OBS+"\",\"package\":\""+pkg+"\""+fields+"}";}
    private static String first(AppCatalogueRanker.Page page){return page.apps.get(0).packageName;}
    private static Set<String> names(AppCatalogueRanker.Page page){Set<String> out=new java.util.LinkedHashSet<String>();for(AppCatalogueRanker.Entry entry:page.apps)out.add(entry.packageName);return out;}
    private static String repeat(String value,int count){StringBuilder out=new StringBuilder();for(int i=0;i<count;i++)out.append(value);return out.toString();}
    private static void check(boolean yes,String message){assertions++;if(!yes)throw new AssertionError(message);}
}
