package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import org.json.JSONObject;

/** Real target parser and full BackgroundSession.Selection; fixture Android I/O is never invoked. */
public final class BackgroundTaskTargetHostTest {
    private static final String NOTES="com.motorola.stylus",HELPER="org.trillionnium.hepta.webhelper";
    private static final String FLIGHT="查一下2026年11月17日北京到上海的单程机票，1名成人";
    private static final String SHOPPING="查一下小米AX3000T的官网售价";
    private static final String NOTE="记一下，明天下午3点看牙，带上检查资料。";
    private static int cases,assertions;
    private interface Checked {void run()throws Exception;}
    private static void check(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
    private static void test(Checked work)throws Exception{work.run();cases++;}
    private static void reject(Checked work)throws Exception{
        boolean rejected=false;try{work.run();}catch(IllegalArgumentException expected){rejected=true;}
        check(rejected,"invalid scope/provenance must be rejected");cases++;
    }
    private static Set<String> selected(){return new LinkedHashSet<String>(Arrays.asList(NOTES,HELPER));}
    private static BackgroundSession.Selection selection(BackgroundTaskTarget target){
        return new BackgroundSession.Selection(target.packageName,target.effectivePackages,target.originalInitialPackage,
                new LinkedHashSet<String>(target.originalPackages),target.ownerSha256,target.recognition);
    }
    public static void main(String[] argv)throws Exception{
        check(argv.length==1,"one new output path");
        final Set<String> original=selected();
        final BackgroundTaskTarget flight=BackgroundTaskTarget.resolve(FLIGHT,NOTES,original);
        final BackgroundTaskTarget note=BackgroundTaskTarget.resolve(NOTE,HELPER,original);
        final BackgroundTaskTarget shopping=BackgroundTaskTarget.resolve(SHOPPING,NOTES,original);
        test(()->check(HELPER.equals(flight.packageName)&&flight.effectivePackages.equals(Collections.singleton(HELPER)),
                "natural flight chooses only already selected helper"));
        test(()->check(NOTES.equals(note.packageName)&&note.effectivePackages.equals(Collections.singleton(NOTES)),
                "comma note chooses only already selected Notes"));
        test(()->check(HELPER.equals(shopping.packageName)&&shopping.effectivePackages.equals(Collections.singleton(HELPER)),
                "natural public product read chooses only already selected helper"));
        test(()->check(flight.ownerSha256.equals(org.trillionnium.hepta.background.FixedIntentTarget.payloadSha256(FLIGHT))
                &&note.ownerSha256.equals(org.trillionnium.hepta.background.FixedIntentTarget.payloadSha256(NOTE)),
                "original OWNER bytes are not rewritten"));
        test(()->check(original.equals(selected()),"target resolution leaves the saved selection untouched"));
        test(()->{
            original.clear();
            check(flight.originalPackages.size()==2&&flight.effectivePackages.size()==1,"snapshot does not alias caller selection");
        });
        test(()->{
            boolean immutable=false;try{flight.originalPackages.clear();}catch(UnsupportedOperationException expected){immutable=true;}
            check(immutable,"original selection evidence is immutable");
            immutable=false;try{flight.effectivePackages.clear();}catch(UnsupportedOperationException expected){immutable=true;}
            check(immutable,"effective selection is immutable");
        });
        test(()->check(BackgroundTaskTarget.resolve("查看当前页面",NOTES,selected())==null,
                "unrecognized generic instruction keeps explicit existing selection path"));
        test(()->check(NOTES.equals(BackgroundTaskTarget.resolve("记一下：带上检查资料。",HELPER,selected()).packageName),
                "existing colon recognition preserves target routing"));
        reject(()->BackgroundTaskTarget.resolve(FLIGHT,NOTES,Collections.singleton(NOTES)));
        reject(()->BackgroundTaskTarget.resolve(SHOPPING,NOTES,Collections.singleton(NOTES)));
        reject(()->BackgroundTaskTarget.resolve(NOTE,HELPER,Collections.singleton(HELPER)));
        reject(()->BackgroundTaskTarget.resolve(FLIGHT,"outside.pkg",selected()));
        reject(()->BackgroundTaskTarget.resolve(FLIGHT,NOTES,Collections.<String>emptySet()));
        reject(()->BackgroundTaskTarget.resolve(FLIGHT,NOTES,new LinkedHashSet<String>(Arrays.asList(NOTES,HELPER,"bad/package"))));
        reject(()->BackgroundTaskTarget.resolve(FLIGHT,NOTES,new LinkedHashSet<String>(
                Arrays.asList(NOTES,HELPER,"a.b","a.c","a.d","a.e","a.f"))));
        test(()->{
            JSONObject json=selection(flight).json(),proof=json.getJSONObject("owner_task_selection");
            check("owner_intent_within_explicit_ui_selection".equals(json.getString("bootstrap_source"))
                    &&HELPER.equals(json.getString("bootstrap_package"))&&json.getJSONArray("allowed_packages").length()==1,
                    "effective background lease is a singleton helper");
            check("hepta.owner-task-app-selection.v1".equals(proof.getString("schema"))
                    &&NOTES.equals(proof.getString("original_ui_initial_package"))
                    &&proof.getJSONArray("original_ui_allowed_packages").length()==2
                    &&proof.getBoolean("effective_scope_strictly_smaller")&&proof.getBoolean("initial_app_changed"),
                    "original selection and real narrowing remain explicit");
            check(!proof.getBoolean("grants_tool_authority")&&!proof.getBoolean("changes_saved_preferences")
                    &&!proof.getBoolean("package_from_model_or_screen")&&!json.getBoolean("bootstrap_model_issued"),
                    "selection proof never grants authority or changes preferences");
        });
        test(()->{
            JSONObject old=new BackgroundSession.Selection(NOTES,selected()).json();
            check("owner_selected_initial_app".equals(old.getString("bootstrap_source"))
                    &&old.getJSONArray("allowed_packages").length()==2&&!old.has("owner_task_selection"),
                    "legacy two-argument selection keeps its old JSON semantics");
        });
        test(()->{
            BackgroundTaskTarget one=BackgroundTaskTarget.resolve(FLIGHT,HELPER,Collections.singleton(HELPER));
            JSONObject proof=selection(one).json().getJSONObject("owner_task_selection");
            check(!proof.getBoolean("effective_scope_strictly_smaller")&&!proof.getBoolean("initial_app_changed"),
                    "already singleton selection does not claim a narrowing or app change");
        });
        reject(()->new BackgroundSession.Selection(HELPER,Collections.singleton(HELPER),NOTES,Collections.singleton(NOTES),
                flight.ownerSha256,flight.recognition));
        reject(()->new BackgroundSession.Selection(HELPER,selected(),NOTES,selected(),flight.ownerSha256,flight.recognition));
        reject(()->new BackgroundSession.Selection(HELPER,Collections.singleton(HELPER),"outside.pkg",selected(),
                flight.ownerSha256,flight.recognition));
        reject(()->new BackgroundSession.Selection(HELPER,Collections.singleton(HELPER),NOTES,selected(),"bad",flight.recognition));
        reject(()->new BackgroundSession.Selection(HELPER,Collections.singleton(HELPER),NOTES,selected(),null,flight.recognition));
        reject(()->new BackgroundSession.Selection(HELPER,Collections.singleton(HELPER),NOTES,selected(),flight.ownerSha256,null));
        reject(()->new BackgroundSession.Selection(HELPER,Collections.singleton(HELPER),NOTES,selected(),flight.ownerSha256,"bad rule"));
        JSONObject result=new JSONObject().put("schema","hepta.background-owner-task-target-host.v1")
                .put("cases",cases).put("assertions",assertions).put("all_pass",true)
                .put("actual_target_parser",true).put("actual_full_background_selection",true)
                .put("android_io_fixture_only",true).put("android_runtime",false).put("phone_actions",0)
                .put("preferences_written",false).put("model_or_business_verified",false);
        Files.write(Paths.get(argv[0]),(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
        System.out.println("actual target/selection cases="+cases+" assertions="+assertions);
    }
}
