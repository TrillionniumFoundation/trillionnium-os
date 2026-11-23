package org.trillionnium.hepta.local;

import android.content.Context;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.trillionnium.hepta.background.FixedIntentTarget;
import org.trillionnium.hepta.background.ProfileTarget;

/** Explicit UI preferences only. A list entry is not an authorization, task or lease.
 * The original manual background-ui-choice-v1 preference is never read or written here. */
final class BackgroundAutoTargetPreferences {
    static final String SCHEMA="hepta.background-auto-targets.v1";
    static final String NOTES="com.motorola.stylus";
    static final String PERSONAL="personal_independent",PROFILE="profile_independent";
    private static final String FILE="background-auto-targets-v1",KEY="settings";
    static final int MAX_TARGETS=6,MAX_BYTES=65536;

    static final class Entry {
        final BackgroundUiPreferences.Selection choice;
        final String instanceKey,identitySha256,displayMode,modelProfile,compute;
        private Entry(BackgroundUiPreferences.Selection choice,String displayMode,String modelProfile,String compute){
            need(choice!=null&&choice.packages.size()==1&&choice.packages.containsKey(choice.initial),"自动目标必须是单个应用实例");
            ProfileTarget p=choice.profileTarget;
            if(p==null){
                BackgroundUiPreferences.Installed installed=choice.packages.get(choice.initial);
                need(NOTES.equals(choice.initial)&&installed.uid>=10000&&installed.uid<90000&&PERSONAL.equals(displayMode),
                        "个人空间自动目标仅支持已明确选择的备忘录");
                instanceKey="personal:0:"+choice.initial;
            }else{
                need(p.profile.userId>0&&p.packageName.equals(choice.initial)&&PROFILE.equals(displayMode),"工作资料自动目标身份或显示方式不一致");
                instanceKey="profile:"+p.profile.userId+":"+p.profile.serial+":"+p.packageName;
            }
            boolean supported=ModelProfile.LFM3.id.equals(modelProfile)
                    ||(p!=null&&ProfileTarget.CTRIP.equals(choice.initial)&&ModelProfile.GUI_OWL_4B.id.equals(modelProfile));
            need(supported&&"npu".equals(compute),"自动目标的首选模型组合不受支持");
            this.choice=choice;this.displayMode=displayMode;this.modelProfile=modelProfile;this.compute=compute;
            StringBuilder canonical=new StringBuilder();field(canonical,"hepta.auto-target-entry.v1");
            field(canonical,instanceKey);field(canonical,choice.initial);field(canonical,displayMode);field(canonical,modelProfile);field(canonical,compute);
            BackgroundUiPreferences.Installed installed=choice.packages.get(choice.initial);
            field(canonical,Integer.toString(installed.uid));for(String signer:installed.signers)field(canonical,signer);
            field(canonical,p==null?"":p.wire());identitySha256=hash(canonical.toString());
        }
        Entry withModel(ModelProfile profile){return new Entry(choice,displayMode,profile.id,compute);}
        String packageName(){return choice.initial;}
        boolean independentProfile(){return PROFILE.equals(displayMode);}
        boolean independentPersonal(){return PERSONAL.equals(displayMode);}
        String label(){return choice.profileTarget==null?"备忘录 · 个人空间":choice.profileTarget.appLabel()+" · 工作资料 "+choice.profileTarget.profile.userId;}
        String modelLabel(){return ModelProfile.GUI_OWL_4B.id.equals(modelProfile)?"GUI-Owl 4B · 语言 NPU + 图像 GPU":"LFM3-1.7B · NPU";}
        boolean matches(LocalRuntimeConfig actual){
            return actual!=null&&modelProfile.equals(actual.profile.id)&&compute.equals(actual.compute)
                    &&actual.contextTokens==8192&&actual.threads==4&&!actual.visualObservationOnly;
        }
        /** Same checks as the old explicit choice. The original broker still freshly
         * checks a managed ProfileTarget before it may create or launch anything. */
        void requireCurrent(Context context)throws Exception{
            Set<String> launchable=new TreeSet<String>();
            if(choice.profileTarget!=null||context.getPackageManager().getLaunchIntentForPackage(choice.initial)!=null)launchable.add(choice.initial);
            BackgroundUiPreferences.requireCurrent(context,choice,Collections.singleton(choice.initial),choice.initial,launchable);
        }
        JSONObject json()throws Exception{
            JSONObject out=new JSONObject().put("package",choice.initial).put("display_mode",displayMode)
                    .put("model_profile",modelProfile).put("compute",compute).put("identity_sha256",identitySha256);
            if(choice.profileTarget!=null)out.put("profile_target_wire",choice.profileTarget.wire());
            else{BackgroundUiPreferences.Installed installed=choice.packages.get(choice.initial);
                out.put("uid",installed.uid).put("signers",new JSONArray(installed.signers));}
            return out;
        }
    }

    static final class Snapshot {
        final boolean automatic;
        final List<Entry> targets;
        final String sha256;
        Snapshot(boolean automatic,List<Entry> targets){
            need(targets!=null&&targets.size()<=MAX_TARGETS&&(!automatic||!targets.isEmpty()),"自动选择需要保存 1 至 6 个明确目标");
            TreeMap<String,Entry> unique=new TreeMap<String,Entry>();
            Map<Integer,Long> users=new TreeMap<Integer,Long>();Map<Long,Integer> serials=new TreeMap<Long,Integer>();
            for(Entry item:targets){
                need(item!=null&&unique.put(item.instanceKey,item)==null,"自动目标实例重复");
                ProfileTarget p=item.choice.profileTarget;
                if(p!=null){Long serial=users.put(p.profile.userId,p.profile.serial);Integer user=serials.put(p.profile.serial,p.profile.userId);
                    need((serial==null||serial.longValue()==p.profile.serial)&&(user==null||user.intValue()==p.profile.userId),"工作资料用户与序号矛盾");}
            }
            this.automatic=automatic;this.targets=Collections.unmodifiableList(new ArrayList<Entry>(unique.values()));
            StringBuilder canonical=new StringBuilder();field(canonical,SCHEMA);field(canonical,Boolean.toString(automatic));
            for(Entry item:this.targets){field(canonical,item.instanceKey);field(canonical,item.identitySha256);}
            sha256=hash(canonical.toString());
        }
        Snapshot withAutomatic(boolean enabled){return new Snapshot(enabled,targets);}
        Entry entry(String key){for(Entry item:targets)if(item.instanceKey.equals(key))return item;return null;}
    }

    static Snapshot empty(){return new Snapshot(false,Collections.<Entry>emptyList());}
    static Entry captureNotes(Context context)throws Exception{
        Set<String> selected=Collections.singleton(NOTES);
        need(context.getPackageManager().getLaunchIntentForPackage(NOTES)!=null,"未找到个人空间的备忘录");
        return new Entry(BackgroundUiPreferences.capture(context,selected,NOTES,selected),PERSONAL,ModelProfile.LFM3.id,"npu");
    }
    static Entry captureProfile(ProfileTarget actual){
        need(actual!=null,"工作资料目标缺失");
        return new Entry(BackgroundUiPreferences.captureProfile(actual),PROFILE,
                ProfileTarget.CTRIP.equals(actual.packageName)?ModelProfile.GUI_OWL_4B.id:ModelProfile.LFM3.id,"npu");
    }
    static Snapshot load(Context context)throws Exception{
        Map<String,?> values=context.getSharedPreferences(FILE,Context.MODE_PRIVATE).getAll();
        if(!values.containsKey(KEY))return empty();
        Object raw=values.get(KEY);need(raw instanceof String,"自动目标偏好格式无效");return decode((String)raw);
    }
    static Snapshot decode(String raw)throws Exception{
        need(raw!=null&&raw.getBytes(StandardCharsets.UTF_8).length<=MAX_BYTES,"自动目标偏好超出上限");
        JSONTokener tokens=new JSONTokener(raw);Object decoded=tokens.nextValue();
        need(decoded instanceof JSONObject&&tokens.nextClean()==0,"自动目标偏好包含额外内容");
        JSONObject root=(JSONObject)decoded;keys(root,"schema","automatic","targets","sha256");
        need(SCHEMA.equals(root.get("schema"))&&root.get("automatic") instanceof Boolean&&root.get("targets") instanceof JSONArray,"自动目标偏好类型不一致");
        JSONArray rows=root.getJSONArray("targets");need(rows.length()<=MAX_TARGETS,"自动目标数量超出上限");List<Entry> result=new ArrayList<Entry>();
        for(int i=0;i<rows.length();i++){
            Object row=rows.get(i);need(row instanceof JSONObject,"自动目标条目格式无效");JSONObject value=(JSONObject)row;
            boolean profile=value.has("profile_target_wire");
            if(profile)keys(value,"package","display_mode","model_profile","compute","identity_sha256","profile_target_wire");
            else keys(value,"package","display_mode","model_profile","compute","identity_sha256","uid","signers");
            String pkg=string(value,"package");BackgroundUiPreferences.Selection choice;
            if(profile){ProfileTarget actual=ProfileTarget.fromWire(string(value,"profile_target_wire"));need(actual.packageName.equals(pkg),"自动目标包与资料身份不一致");choice=BackgroundUiPreferences.captureProfile(actual);}
            else{
                Object uid=value.get("uid");need(uid instanceof Integer||uid instanceof Long,"自动目标 UID 类型无效");long n=((Number)uid).longValue();
                need(n>=10000&&n<90000&&value.get("signers") instanceof JSONArray,"个人目标 UID 或签名无效");
                JSONArray hashes=value.getJSONArray("signers");need(hashes.length()>0&&hashes.length()<=4,"个人目标签名数量无效");Set<String> signers=new TreeSet<String>();
                for(int j=0;j<hashes.length();j++){Object h=hashes.get(j);need(h instanceof String&&((String)h).matches("[0-9a-f]{64}")&&signers.add((String)h),"个人目标签名无效或重复");}
                Map<String,BackgroundUiPreferences.Installed> installed=new TreeMap<String,BackgroundUiPreferences.Installed>();installed.put(pkg,new BackgroundUiPreferences.Installed((int)n,signers));choice=new BackgroundUiPreferences.Selection(pkg,installed);
            }
            Entry item=new Entry(choice,string(value,"display_mode"),string(value,"model_profile"),string(value,"compute"));
            need(item.identitySha256.equals(string(value,"identity_sha256")),"自动目标身份摘要不一致");result.add(item);
        }
        Snapshot snapshot=new Snapshot(root.getBoolean("automatic"),result);need(snapshot.sha256.equals(string(root,"sha256")),"自动目标列表摘要不一致");return snapshot;
    }
    static String encode(Snapshot snapshot)throws Exception{
        need(snapshot!=null,"自动目标列表缺失");JSONArray rows=new JSONArray();for(Entry item:snapshot.targets)rows.put(item.json());
        String raw=new JSONObject().put("schema",SCHEMA).put("automatic",snapshot.automatic).put("targets",rows).put("sha256",snapshot.sha256).toString();
        need(raw.getBytes(StandardCharsets.UTF_8).length<=MAX_BYTES,"自动目标偏好超出上限");return raw;
    }
    static void save(Context context,Snapshot snapshot)throws Exception{
        String raw=encode(snapshot);if(!context.getSharedPreferences(FILE,Context.MODE_PRIVATE).edit().putString(KEY,raw).commit())throw new IllegalStateException("自动目标偏好未保存");
    }
    static void requireSame(Context context,Snapshot expected)throws Exception{
        need(expected!=null&&expected.sha256.equals(load(context).sha256),"自动目标偏好已变化，请重新开始");
    }
    private static String string(JSONObject object,String key)throws Exception{Object value=object.get(key);need(value instanceof String,"自动目标字符串类型无效");return (String)value;}
    private static void keys(JSONObject object,String... expected)throws Exception{Set<String> actual=new TreeSet<String>();for(Iterator<String> i=object.keys();i.hasNext();)actual.add(i.next());Set<String> required=new TreeSet<String>();Collections.addAll(required,expected);need(actual.equals(required),"自动目标字段不一致");}
    static void field(StringBuilder out,String value){need(value!=null,"自动目标绑定字段缺失");out.append(value.getBytes(StandardCharsets.UTF_8).length).append(':').append(value).append('\n');}
    static String hash(String value){return FixedIntentTarget.payloadSha256(value);}
    static void need(boolean condition,String reason){if(!condition)throw new IllegalArgumentException(reason);}
    private BackgroundAutoTargetPreferences(){}
}
