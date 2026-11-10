package org.trillionnium.hepta.local;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.*;
import org.json.*;
import static org.trillionnium.hepta.local.QualificationScopeHostTest.*;

/** Exercise production catalogue, dispatch and controller with synthetic Android IO. */
final class ScopedCatalogueHostTest {
    private static final String BAIDU="com.baidu.searchbox",MAP="com.baidu.BaiduMap";
    private ScopedCatalogueHostTest(){}
    static void outsiders(Env e){
        e.service.launchable.put(BAIDU,"百度");e.service.launchable.put(MAP,"百度地图");
        for(int i=0;i<20;i++)e.service.launchable.put("com.aaa.foreign"+i,"百度 "+i);
    }
    static Set<String> packages(AppCatalogueRanker.Page page){
        Set<String> values=new TreeSet<String>();for(AppCatalogueRanker.Entry row:page.apps)values.add(row.packageName);return values;
    }
    static HeptaAccessibilityService.ActionOutcome search(Env e,String query,int offset)throws Exception{
        JSONObject request=new JSONObject(e.actionText("find_app",SETTINGS));request.put("query",query).put("offset",offset);
        return e.service.execute(ActionDecision.parse(request.toString(),DecisionGrammar.SCHEMA));
    }
    static void run()throws Exception{
        test("scoped_catalogue_filters_before_owner_ranking_and_pagination",()->{try(Env e=new Env(true)){
            outsiders(e);e.bind(e.scopeSha);
            AppCatalogueRanker.Page page=e.service.appCatalogue(e.task,"先打开百度，再看百度地图");
            check(packages(page).equals(new TreeSet<String>(Arrays.asList(SETTINGS,CALC,HOME))),"scope must exclude unrelated installed apps before first-page ranking");
            check(page.totalApps==3&&page.matchingApps==3&&page.nextOffset(page.apps.size())==-1,"counts and pagination describe only the scoped snapshot");
            Map<String,String> expected=new HashMap<String,String>();for(String pkg:packages(page))expected.put(pkg,e.service.launchable.get(pkg));
            check(page.catalogueSha256.equals(new AppCatalogueRanker(expected,"").catalogueSha256),"catalogue identity must hash only visible eligible entries");
            check(e.service.effects()==0&&!e.bound.evidence().getBoolean("scope_refused"),"catalogue projection is read-only and does not trip dispatch gate");
        }});
        test("scoped_find_app_cannot_reintroduce_unavailable_packages_or_labels",()->{try(Env e=new Env(true)){
            outsiders(e);e.bind(e.scopeSha);e.service.appCatalogue(e.task,"设置");
            for(String query:new String[]{"百度",BAIDU,MAP,"synthetic-foreign"}){
                HeptaAccessibilityService.ActionOutcome result=search(e,query,0);
                check(result.accepted&&!result.dispatched&&result.appCatalogue!=null,"find_app remains successful read-only lookup");
                check(result.appCatalogue.apps.isEmpty()&&result.appCatalogue.matchingApps==0&&result.appCatalogue.nextOffset(0)==-1,"unauthorized query must have no candidates or phantom page");
            }
            HeptaAccessibilityService.ActionOutcome allowed=search(e,"计算器",0);
            check(packages(allowed.appCatalogue).equals(Collections.singleton(CALC)),"authorized tool result remains usable");
            check(e.service.effects()==0,"search never opens any app");
        }});
        test("scoped_find_app_retains_immutable_filtered_snapshot",()->{try(Env e=new Env(true)){
            e.bind(e.scopeSha);AppCatalogueRanker.Page original=e.service.appCatalogue(e.task,"设置");
            outsiders(e);e.service.launchable.put(CALC,"changed after snapshot");
            AppCatalogueRanker.Page page=search(e,"",0).appCatalogue;
            check(original.catalogueSha256.equals(page.catalogueSha256)&&packages(original).equals(packages(page)),"later launcher refresh cannot expand or relabel task snapshot");
            check(search(e,"计算器",0).appCatalogue.matchingApps==1,"snapshot label remains stable");
            check(search(e,"",page.totalApps).appCatalogue.apps.isEmpty(),"end offset remains empty without out-of-scope tail");
        }});
        test("unrestricted_catalogue_preserves_full_discovery_and_paging",()->{try(Env e=new Env(false)){
            outsiders(e);e.bind(null);AppCatalogueRanker.Page first=e.service.appCatalogue(e.task,"百度");
            check(first.totalApps==e.service.launchable.size(),"unrestricted total unchanged");
            Set<String> seen=new TreeSet<String>();AppCatalogueRanker.Page page=first;
            while(true){seen.addAll(packages(page));int next=page.nextOffset(page.apps.size());if(next<0)break;page=search(e,"",next).appCatalogue;}
            check(seen.equals(e.service.launchable.keySet()),"all ordinary installed apps remain reachable across pages");
            check(packages(search(e,BAIDU,0).appCatalogue).equals(Collections.singleton(BAIDU)),"ordinary search remains unrestricted");
        }});
        test("catalogue_rejects_missing_or_changed_task_scope",()->{
            try(Env e=new Env(true)){check(e.service.acquireTask(e.task,()->{}),"lease");rejects(()->e.service.appCatalogue(e.task,"设置"));check(e.service.appDiscovery==null,"unbound task publishes no snapshot");}
            try(Env e=new Env(true)){e.bind(e.scopeSha);Files.delete(e.dir.resolve(QualificationScope.FILE_NAME));rejects(()->e.service.appCatalogue(e.task,"设置"));check(e.service.appDiscovery==null,"changed scope publishes no snapshot");}
            try(Env e=new Env(true)){e.bind(e.scopeSha);e.service.releaseTask(e.task);rejects(()->e.service.appCatalogue(e.task,"设置"));check(e.service.appDiscovery==null,"retired lease publishes no snapshot");}
        });
        test("controller_prompt_and_grammar_match_scoped_initial_and_search_pages",()->{try(Env e=new Env(true)){
            outsiders(e);final int[] calls={0};final List<String> prompts=new ArrayList<String>();
            LocalInference model=new LocalInference(){
                public LocalRuntimeConfig configuration(){return e.runtime;}
                public Handle generate(String prompt,String system,File image,DecisionGrammar grammar,int max,long timeout,Callback callback){
                    try{calls[0]++;prompts.add(prompt);
                    for(String pkg:new String[]{BAIDU,MAP,FOREIGN[0],FOREIGN[1],FOREIGN[2],FOREIGN[3]}){
                        check(!prompt.contains(pkg),"unavailable app package leaked into model prompt");
                        check(!grammar.appLabels.labels.containsKey(pkg),"unavailable app present in actual open grammar");
                    }
                    if(calls[0]==1)check(grammar.appLabels.labels.containsKey(CALC),"available calculator must remain in grammar");
                    else check(grammar.appLabels.labels.isEmpty()&&!grammar.actions.contains("open"),"empty scoped search must remove open from next grammar");
                    JSONObject action=new JSONObject().put("reason","synthetic scoped catalogue test").put("observation_id",e.service.current.id).put("package",SETTINGS);
                    if(calls[0]==1)action.put("action","find_app").put("query","百度").put("offset",0);
                    else action.put("action","done").put("status","partial").put("summary","No scoped candidate");
                    callback.onSuccess(action.toString(),String.format(Locale.ROOT,"%032x",calls[0]));return ()->{};
                    }catch(Exception error){throw new IllegalStateException(error);}
                }
            };
            e.controller=new LocalTaskController(e.service,model);final LocalTaskController.TaskResult[] result={null};CountDownLatch completed=new CountDownLatch(1);
            check(e.controller.start("查看本机允许的应用",e.scopeSha,new LocalTaskController.Listener(){public void onState(String value){}public void onFinished(LocalTaskController.TaskResult value){result[0]=value;completed.countDown();}}),"controller accepted synthetic task");
            check(completed.await(10,TimeUnit.SECONDS),"controller finished");
            check(calls[0]==2&&"partial".equals(result[0].status)&&!result[0].modelReportedSuccess&&e.service.effects()==0,"actual controller made one lookup and cleanly stopped");
            JSONObject initial=new JSONObject(new String(Files.readAllBytes(result[0].evidenceDirectory.toPath().resolve("initial-app-catalogue.json")),StandardCharsets.UTF_8));
            check(initial.getInt("total_apps")==3,"recorded initial catalogue uses same scoped domain");
        }});
    }
}
