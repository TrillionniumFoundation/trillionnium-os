package org.trillionnium.hepta.local;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import org.json.JSONArray;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/** Remember UI choices only. A saved choice is never a task, authorization, or lease. */
final class BackgroundUiPreferences {
    private static final String FILE="background-ui-choice-v1";
    private static final String SCHEMA="hepta.background-ui-choice.v1";
    private static final String MODE="enabled",SELECTION="selection";
    private static final int MAX_BYTES=8192;

    static final class Installed {
        final int uid;
        final List<String> signers;
        Installed(int uid,Set<String> signers){
            if(uid<0||signers==null||signers.isEmpty()||signers.size()>4)
                throw new IllegalArgumentException("background choice identity missing");
            this.uid=uid;this.signers=Collections.unmodifiableList(new ArrayList<String>(new TreeSet<String>(signers)));
        }
        boolean same(Installed other){return other!=null&&uid==other.uid&&signers.equals(other.signers);}
    }
    static final class Selection {
        final String initial;
        final Map<String,Installed> packages;
        Selection(String initial,Map<String,Installed> values){
            if(values==null||values.isEmpty()||values.size()>6||!values.containsKey(initial))
                throw new IllegalArgumentException("background choice range missing");
            for(Map.Entry<String,Installed> item:values.entrySet()){
                packageName(item.getKey());if(item.getValue()==null)throw new IllegalArgumentException("background choice identity missing");
            }
            this.initial=initial;this.packages=Collections.unmodifiableMap(new TreeMap<String,Installed>(values));
        }
        Selection withInitial(String value){return new Selection(value,packages);}
    }

    private static SharedPreferences preferences(Context context){
        return context.getSharedPreferences(FILE,Context.MODE_PRIVATE);
    }
    static boolean mode(Context context){
        Map<String,?> values=preferences(context).getAll();
        if(!values.containsKey(MODE))return false;
        Object value=values.get(MODE);
        if(!(value instanceof Boolean))throw new IllegalStateException("saved background mode is malformed");
        return ((Boolean)value).booleanValue();
    }
    static void saveMode(Context context,boolean enabled){
        if(!preferences(context).edit().putBoolean(MODE,enabled).commit())
            throw new IllegalStateException("background mode was not persisted");
    }
    static Selection load(Context context)throws Exception{
        Map<String,?> values=preferences(context).getAll();
        if(!values.containsKey(SELECTION))return null;
        Object value=values.get(SELECTION);
        if(!(value instanceof String))throw new IllegalStateException("saved background choice is malformed");
        String raw=(String)value;
        if(raw.getBytes(StandardCharsets.UTF_8).length>MAX_BYTES)throw new IllegalStateException("saved background choice is too large");
        JSONObject root=new JSONObject(raw);keys(root,"schema","initial","packages");
        if(!SCHEMA.equals(root.get("schema"))||!(root.get("initial") instanceof String)
                ||!(root.get("packages") instanceof JSONArray))
            throw new IllegalStateException("saved background choice schema differs");
        JSONArray items=root.getJSONArray("packages");
        if(items.length()<1||items.length()>6)throw new IllegalStateException("saved background choice count differs");
        Map<String,Installed> selected=new TreeMap<String,Installed>();
        for(int index=0;index<items.length();index++){
            JSONObject item=items.getJSONObject(index);keys(item,"package","uid","signers");
            if(!(item.get("package") instanceof String)||!(item.get("signers") instanceof JSONArray))
                throw new IllegalStateException("saved background identity type differs");
            String pkg=(String)item.get("package");packageName(pkg);
            Object uid=item.get("uid");
            if(!(uid instanceof Integer)&&!(uid instanceof Long))throw new IllegalStateException("saved background UID type differs");
            long number=((Number)uid).longValue();
            if(number<0||number>Integer.MAX_VALUE)throw new IllegalStateException("saved background UID differs");
            JSONArray hashes=item.getJSONArray("signers");Set<String> signers=new TreeSet<String>();
            if(hashes.length()<1||hashes.length()>4)throw new IllegalStateException("saved background signer count differs");
            for(int j=0;j<hashes.length();j++){
                Object hash=hashes.get(j);
                if(!(hash instanceof String)||!((String)hash).matches("[0-9a-f]{64}")||!signers.add((String)hash))
                    throw new IllegalStateException("saved background signer differs");
            }
            if(selected.put(pkg,new Installed((int)number,signers))!=null)
                throw new IllegalStateException("saved background package duplicated");
        }
        return new Selection(root.getString("initial"),selected);
    }
    static void save(Context context,Selection selection)throws Exception{
        JSONArray items=new JSONArray();
        for(Map.Entry<String,Installed> item:selection.packages.entrySet()){
            Installed value=item.getValue();
            items.put(new JSONObject().put("package",item.getKey()).put("uid",value.uid).put("signers",new JSONArray(value.signers)));
        }
        String raw=new JSONObject().put("schema",SCHEMA).put("initial",selection.initial).put("packages",items).toString();
        if(raw.getBytes(StandardCharsets.UTF_8).length>MAX_BYTES)throw new IllegalStateException("background choice is too large");
        if(!preferences(context).edit().putString(SELECTION,raw).commit())
            throw new IllegalStateException("background choice was not persisted");
    }
    /** Called only after a visible owner selection, never during restore. */
    static Selection capture(Context context,Set<String> selected,String initial,Set<String> launchable)throws Exception{
        if(selected==null||selected.isEmpty()||selected.size()>6||!selected.contains(initial))
            throw new IllegalArgumentException("select a background range and initial app");
        Map<String,Installed> identities=new TreeMap<String,Installed>();
        for(String pkg:selected){
            if(launchable==null||!launchable.contains(pkg))throw new IllegalStateException("selected app is not launchable");
            identities.put(pkg,installed(context,pkg));
        }
        return new Selection(initial,identities);
    }
    /** Fresh OS identity check. An installation change requires a new visible selection. */
    static void requireCurrent(Context context,Selection saved,Set<String> selected,String initial,Set<String> launchable)throws Exception{
        if(saved==null||selected==null||!saved.packages.keySet().equals(new TreeSet<String>(selected))
                ||!saved.initial.equals(initial))throw new IllegalStateException("background choice needs confirmation");
        for(Map.Entry<String,Installed> item:saved.packages.entrySet()){
            if(launchable==null||!launchable.contains(item.getKey())||!item.getValue().same(installed(context,item.getKey())))
                throw new IllegalStateException("selected app installation changed; choose the range again");
        }
    }
    private static Installed installed(Context context,String pkg)throws Exception{
        packageName(pkg);
        PackageInfo info=context.getPackageManager().getPackageInfo(pkg,PackageManager.GET_SIGNING_CERTIFICATES);
        ApplicationInfo application=info.applicationInfo;
        if(!pkg.equals(info.packageName)||application==null||!pkg.equals(application.packageName)||!application.enabled||application.uid<0||info.signingInfo==null)
            throw new IllegalStateException("selected app installation is unavailable");
        Signature[] values=info.signingInfo.getApkContentsSigners();
        if(values==null||values.length<1||values.length>4)throw new IllegalStateException("selected app signer is unavailable");
        Set<String> hashes=new TreeSet<String>();
        for(Signature value:values){
            if(value==null)throw new IllegalStateException("selected app signer is unavailable");
            byte[] digest=MessageDigest.getInstance("SHA-256").digest(value.toByteArray());
            StringBuilder out=new StringBuilder(64);
            for(byte x:digest){int n=x&255;out.append(Character.forDigit(n>>>4,16)).append(Character.forDigit(n&15,16));}
            if(!hashes.add(out.toString()))throw new IllegalStateException("selected app signer duplicated");
        }
        return new Installed(application.uid,hashes);
    }
    private static void keys(JSONObject value,String...expected)throws Exception{
        Set<String> actual=new TreeSet<String>();for(Iterator<String> it=value.keys();it.hasNext();)actual.add(it.next());
        Set<String> wanted=new TreeSet<String>();Collections.addAll(wanted,expected);
        if(!actual.equals(wanted))throw new IllegalStateException("saved background choice fields differ");
    }
    private static void packageName(String pkg){
        if(pkg==null||pkg.length()>255||!pkg.matches("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+"))
            throw new IllegalArgumentException("invalid background package name");
    }
}
