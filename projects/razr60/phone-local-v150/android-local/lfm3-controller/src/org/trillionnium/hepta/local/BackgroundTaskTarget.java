package org.trillionnium.hepta.local;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.trillionnium.hepta.background.FixedIntentTarget;
import org.trillionnium.hepta.background.FixedIntentTools;
import org.trillionnium.hepta.local.web.WebFlightGoal;
import org.trillionnium.hepta.local.web.WebShoppingGoal;

/** Narrow one recognized OWNER task within an already explicit UI app selection.
 * This supplies no tool authority, permission grant, package discovery or dispatch.
 */
final class BackgroundTaskTarget {
    static final String HELPER="org.trillionnium.hepta.webhelper";
    static final String NATIVE_APP="native_app",WEB_HELPER="web_helper";
    /** Pure identity interface; the real final BackgroundSession.Selection implements it. */
    interface SelectionBinding { BackgroundTaskTarget executionTarget(); }
    final String packageName,recognition,ownerSha256,originalInitialPackage;
    final List<String> originalPackages;
    final Set<String> effectivePackages;
    final String route,targetSha256;
    final boolean explicitSelection;
    final NativeAppGoal nativeGoal;
    private BackgroundTaskTarget(String owner,String target,String recognition,String initial,Set<String> selected){
        this(owner,target,recognition,initial,selected,false,null);
    }
    private BackgroundTaskTarget(String owner,String target,String recognition,String initial,Set<String> selected,
                                 boolean explicitSelection,NativeAppGoal nativeGoal){
        this.packageName=target;this.recognition=recognition;
        ownerSha256=FixedIntentTarget.payloadSha256(owner);originalInitialPackage=initial;
        TreeSet<String> copy=new TreeSet<String>(selected);
        originalPackages=Collections.unmodifiableList(new ArrayList<String>(copy));
        effectivePackages=Collections.singleton(target);
        this.explicitSelection=explicitSelection;this.nativeGoal=nativeGoal;
        route=HELPER.equals(target)?WEB_HELPER:NATIVE_APP;
        if(explicitSelection&&!target.equals(initial))throw new IllegalArgumentException("显式起始应用不能被任务推断替换");
        if(nativeGoal!=null){
            nativeGoal.requireBinding(owner,target);
            if(!NATIVE_APP.equals(route))throw new IllegalArgumentException("原生目标不能绑定网页执行路线");
        }
        StringBuilder binding=new StringBuilder();
        for(String value:new String[]{"hepta.explicit-task-target.v1",ownerSha256,route,target,initial,recognition,
                Boolean.toString(explicitSelection),nativeGoal==null?"":nativeGoal.contractSha256})field(binding,value);
        for(String value:originalPackages)field(binding,value);
        field(binding,"effective");for(String value:effectivePackages)field(binding,value);
        targetSha256=FixedIntentTarget.payloadSha256(binding.toString());
    }
    /** Ordinary UI entry. Its explicit initial app wins; OWNER is never rewritten.
     * The old resolver below remains the legacy helper/Notes recognition contract,
     * but this entry never calls its automatic helper selection for a native app.
     */
    static BackgroundTaskTarget resolveExplicitSelection(String owner,String initial,Set<String> selected){
        if(owner==null||owner.isEmpty()||selected==null||selected.isEmpty()||selected.size()>6
                ||initial==null||!selected.contains(initial))
            throw new IllegalArgumentException("请先输入任务并选择后台可操作的起始应用");
        for(String value:selected)if(value==null||!value.matches("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+"))
            throw new IllegalArgumentException("后台应用范围无效，请重新选择");
        if(HELPER.equals(initial)){
            BackgroundTaskTarget legacy=resolve(owner,initial,selected);
            if(legacy==null||!HELPER.equals(legacy.packageName))
                throw new IllegalArgumentException("已选官网查询工具需要其支持的完整网页查询指令");
            return new BackgroundTaskTarget(owner,HELPER,legacy.recognition,initial,selected,true,null);
        }
        NativeAppGoal goal=NativeAppGoal.parse(owner,initial);
        return new BackgroundTaskTarget(owner,initial,goal==null?"explicit_native_app_selection.v1":goal.recognition,
                initial,selected,true,goal);
    }
    boolean webHelper(){return WEB_HELPER.equals(route);}
    void requireOwner(String owner){
        if(owner==null||!ownerSha256.equals(FixedIntentTarget.payloadSha256(owner)))
            throw new IllegalArgumentException("执行目标与原始任务不一致");
        if(nativeGoal!=null)nativeGoal.requireBinding(owner,packageName);
    }
    java.util.Map<String,Object> evidence(){
        java.util.Map<String,Object> value=new java.util.LinkedHashMap<String,Object>();
        value.put("schema","hepta.explicit-task-target.v1");value.put("target_sha256",targetSha256);
        value.put("owner_sha256",ownerSha256);value.put("route",route);value.put("recognition",recognition);
        value.put("explicit_initial_selection",explicitSelection);
        value.put("original_ui_initial_package",originalInitialPackage);value.put("original_ui_allowed_packages",originalPackages);
        value.put("effective_initial_package",packageName);
        value.put("effective_allowed_packages",Collections.unmodifiableList(new ArrayList<String>(effectivePackages)));
        value.put("native_goal",nativeGoal==null?null:nativeGoal.evidence());
        value.put("owner_rewritten",false);value.put("package_from_model_or_screen",false);
        value.put("grants_tool_authority",false);value.put("business_verified",false);
        return Collections.unmodifiableMap(value);
    }
    private static void field(StringBuilder out,String value){
        out.append(value.getBytes(java.nio.charset.StandardCharsets.UTF_8).length).append(':').append(value).append('\n');
    }
    static BackgroundTaskTarget resolve(String owner,String initial,Set<String> selected){
        WebFlightGoal flight=WebFlightGoal.parse(owner);
        WebShoppingGoal shopping=WebShoppingGoal.parse(owner);
        NotesOwnerIntent.Result note=NotesOwnerIntent.parse(owner);
        int matches=(flight==null?0:1)+(shopping==null?0:1)+(note.supported?1:0);
        if(matches==0)return null; // Other tasks keep the explicitly chosen initial app and range.
        if(matches!=1)throw new IllegalArgumentException("任务目标不唯一，请一次只描述一个任务");
        if(selected==null||selected.isEmpty()||selected.size()>6||initial==null||!selected.contains(initial))
            throw new IllegalArgumentException("请先选择后台可操作的应用范围");
        for(String value:selected)if(value==null||!value.matches("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+"))
            throw new IllegalArgumentException("后台应用范围无效，请重新选择");
        String target=note.supported?FixedIntentTools.forAction(FixedIntentTools.NOTES_CREATE).packageName:HELPER;
        if(!selected.contains(target))throw new IllegalArgumentException(note.supported
                ?"请在后台应用范围中选择备忘录":"请在后台应用范围中选择官网查询工具");
        String form=note.supported?note.recognition:flight!=null?flight.recognition:shopping.recognition;
        return new BackgroundTaskTarget(owner,target,form,initial,selected);
    }
}
