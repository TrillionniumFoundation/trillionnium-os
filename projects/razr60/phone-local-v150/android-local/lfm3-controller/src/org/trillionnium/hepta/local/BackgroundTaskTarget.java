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
    final String packageName,recognition,ownerSha256,originalInitialPackage;
    final List<String> originalPackages;
    final Set<String> effectivePackages;
    private BackgroundTaskTarget(String owner,String target,String recognition,String initial,Set<String> selected){
        this.packageName=target;this.recognition=recognition;
        ownerSha256=FixedIntentTarget.payloadSha256(owner);originalInitialPackage=initial;
        TreeSet<String> copy=new TreeSet<String>(selected);
        originalPackages=Collections.unmodifiableList(new ArrayList<String>(copy));
        effectivePackages=Collections.singleton(target);
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
