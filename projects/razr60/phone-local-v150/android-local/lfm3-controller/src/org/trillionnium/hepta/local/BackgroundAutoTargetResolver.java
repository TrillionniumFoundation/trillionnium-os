package org.trillionnium.hepta.local;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.trillionnium.hepta.background.ProfileTarget;

/** Pure full-OWNER matching inside a visibly saved target set. No model, screen
 * text, package discovery, lifecycle mutation or Android authority enters here. */
final class BackgroundAutoTargetResolver {
    static final String SCHEMA="hepta.background-auto-target-resolution.v1";
    static final class Resolution {
        final String owner,ownerSha256;
        final BackgroundAutoTargetPreferences.Snapshot snapshot;
        final List<BackgroundAutoTargetPreferences.Entry> matches;
        private final Map<String,NativeAppGoal> goals;
        private final Map<String,String> recognitions;
        private Resolution(String owner,BackgroundAutoTargetPreferences.Snapshot snapshot,
                List<BackgroundAutoTargetPreferences.Entry> matches,Map<String,NativeAppGoal> goals,Map<String,String> recognitions){
            this.owner=owner;ownerSha256=BackgroundAutoTargetPreferences.hash(owner);this.snapshot=snapshot;
            this.matches=Collections.unmodifiableList(new ArrayList<BackgroundAutoTargetPreferences.Entry>(matches));
            this.goals=Collections.unmodifiableMap(new LinkedHashMap<String,NativeAppGoal>(goals));
            this.recognitions=Collections.unmodifiableMap(new LinkedHashMap<String,String>(recognitions));
        }
        boolean same(String text,BackgroundAutoTargetPreferences.Snapshot current){
            return current!=null&&current.automatic&&owner.equals(text)&&snapshot.sha256.equals(current.sha256);
        }
        BackgroundAutoTargetPreferences.Entry choose(String explicitInstanceKey){
            if(matches.isEmpty())throw new IllegalArgumentException("未明确匹配已保存的目标；请在指令中明确应用或选择手动模式");
            if(explicitInstanceKey==null){
                if(matches.size()!=1)throw new IllegalArgumentException("多个已保存实例符合任务，请明确选择本次实例");
                return matches.get(0);
            }
            for(BackgroundAutoTargetPreferences.Entry item:matches)if(item.instanceKey.equals(explicitInstanceKey))return item;
            throw new IllegalArgumentException("本次目标选择已失效，请重新选择");
        }
        private String recognition(BackgroundAutoTargetPreferences.Entry selected){
            BackgroundAutoTargetPreferences.need(selected!=null&&matches.contains(selected)
                    &&snapshot.entry(selected.instanceKey)==selected,"自动目标不属于同一真实匹配结果");
            String value=recognitions.get(selected.instanceKey);
            BackgroundAutoTargetPreferences.need(value!=null,"自动目标路由依据缺失");
            return value;
        }
        boolean hasCompletionContract(BackgroundAutoTargetPreferences.Entry selected){
            return !OwnerExplicitAppRoute.RECOGNITION.equals(recognition(selected));
        }
        StartSelection confirm(BackgroundAutoTargetPreferences.Entry selected,String nonce,String runtimeId,String configSha){
            String value=recognition(selected);
            return new StartSelection(this,selected,goals.get(selected.instanceKey),value,nonce,runtimeId,configSha);
        }
    }
    /** Immutable provenance of a UI-confirmed singleton. It is not a dispatch permit. */
    static final class StartSelection {
        final String owner,ownerSha256,nonce,runtimeId,configurationSha256,sha256,recognition;
        final BackgroundAutoTargetPreferences.Snapshot snapshot;
        final BackgroundAutoTargetPreferences.Entry entry;
        final NativeAppGoal nativeGoal;
        private StartSelection(Resolution resolution,BackgroundAutoTargetPreferences.Entry entry,NativeAppGoal goal,
                String recognition,String nonce,String runtimeId,String configSha){
            BackgroundAutoTargetPreferences.need(nonce!=null&&nonce.matches("[0-9a-f]{32}")
                    &&runtimeId!=null&&runtimeId.matches("[0-9a-f]{32}")&&configSha!=null&&configSha.matches("[0-9a-f]{64}"),
                    "自动目标开始标识或真实模型代缺失");
            this.owner=resolution.owner;this.ownerSha256=resolution.ownerSha256;this.snapshot=resolution.snapshot;
            this.entry=entry;nativeGoal=goal;this.recognition=recognition;this.nonce=nonce;this.runtimeId=runtimeId;configurationSha256=configSha;
            if(goal!=null)goal.requireBinding(owner,entry.packageName());
            StringBuilder binding=new StringBuilder();
            for(String value:new String[]{SCHEMA,ownerSha256,snapshot.sha256,entry.instanceKey,entry.identitySha256,
                    entry.displayMode,entry.modelProfile,entry.compute,nonce,runtimeId,configSha,recognition})BackgroundAutoTargetPreferences.field(binding,value);
            sha256=BackgroundAutoTargetPreferences.hash(binding.toString());
        }
        void requireOwner(String actual){BackgroundAutoTargetPreferences.need(owner.equals(actual)&&ownerSha256.equals(BackgroundAutoTargetPreferences.hash(actual)),"自动目标与原始任务不一致");}
        Map<String,Object> evidence(){
            Map<String,Object> out=new LinkedHashMap<String,Object>();out.put("schema",SCHEMA);
            out.put("selection_mode","owner_enabled_automatic_saved_targets");out.put("resolution_sha256",sha256);
            out.put("owner_sha256",ownerSha256);out.put("saved_target_list_sha256",snapshot.sha256);
            out.put("selected_instance",entry.instanceKey);out.put("selected_identity_sha256",entry.identitySha256);
            out.put("display_mode",entry.displayMode);out.put("preferred_model_profile",entry.modelProfile);out.put("preferred_compute",entry.compute);
            out.put("start_nonce",nonce);out.put("actual_runtime_generation_id",runtimeId);out.put("actual_runtime_configuration_sha256",configurationSha256);
            out.put("recognition",recognition);out.put("manual_initial_preference_changed",false);
            out.put("model_or_screen_selected_target",false);out.put("grants_dispatch_authority",false);return Collections.unmodifiableMap(out);
        }
    }
    static Resolution resolve(String owner,BackgroundAutoTargetPreferences.Snapshot snapshot,TaskAuthorization original){
        BackgroundAutoTargetPreferences.need(snapshot!=null&&snapshot.automatic&&original!=null,"自动目标模式或原始授权缺失");
        original.requireOwner(owner);
        // Complete business contracts retain priority. In particular, app names
        // in a supported Notes body remain data rather than routing candidates.
        TaskCompletionGate.Contract contract=TaskCompletionGate.Contract.parse(owner,original);
        boolean note=TaskCompletionGate.NOTES.equals(contract.kind);
        List<BackgroundAutoTargetPreferences.Entry> matches=new ArrayList<BackgroundAutoTargetPreferences.Entry>();
        Map<String,NativeAppGoal> goals=new LinkedHashMap<String,NativeAppGoal>();
        Map<String,String> recognitions=new LinkedHashMap<String,String>();
        for(BackgroundAutoTargetPreferences.Entry item:snapshot.targets){
            if(BackgroundAutoTargetPreferences.NOTES.equals(item.packageName())){
                if(note){matches.add(item);recognitions.put(item.instanceKey,contract.recognition);}
            }else if(ProfileTarget.CTRIP.equals(item.packageName())||ProfileTarget.XIAOMI.equals(item.packageName())){
                NativeAppGoal goal=NativeAppGoal.parse(owner,item.packageName());
                if(goal!=null){matches.add(item);goals.put(item.instanceKey,goal);recognitions.put(item.instanceKey,goal.recognition);}
            }
        }
        // This supplies only a target, never a NativeAppGoal or completion proof.
        // A sole saved entry is insufficient: the original OWNER must name it.
        if(matches.isEmpty()&&TaskCompletionGate.UNKNOWN.equals(contract.kind)){
            String explicit=OwnerExplicitAppRoute.packageName(owner);
            if(explicit!=null)for(BackgroundAutoTargetPreferences.Entry item:snapshot.targets)
                if(explicit.equals(item.packageName())){
                    matches.add(item);recognitions.put(item.instanceKey,OwnerExplicitAppRoute.RECOGNITION);
                }
        }
        return new Resolution(owner,snapshot,matches,goals,recognitions);
    }
    private BackgroundAutoTargetResolver(){}
}
