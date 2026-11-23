package org.trillionnium.hepta.local;

import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/** Opt-in qualification policy. Observations and model reasons cannot extend it. */
public final class QualificationScope {
    public static final String FILE_NAME="qualification-scope.json";
    public static final String BUILD_ASSET="hepta-build-identity.json";
    public static final String EXPECTED_EXTRA="expected_scope_sha256";
    public static final java.util.List<String> ROLES=Collections.unmodifiableList(Arrays.asList("settings","search","calculator","launcher"));
    public static final int MAX_CONFIG_BYTES=16384;

    public static final class Violation extends IllegalStateException {
        private static final long serialVersionUID=1L;
        Violation(String message){super("qualification_scope: "+message);}
    }
    static void require(boolean condition,String reason){if(!condition)throw new Violation(reason);}
    public static String hash(byte[] value){
        try{StringBuilder result=new StringBuilder();for(byte b:MessageDigest.getInstance("SHA-256").digest(value))
            result.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return result.toString();}
        catch(Exception error){throw new IllegalStateException(error);}
    }
    public static String ownerHash(String owner){require(owner!=null,"owner missing");return hash(owner.getBytes(StandardCharsets.UTF_8));}
    static boolean sha(String value){return value!=null&&value.matches("[0-9a-f]{64}");}
    public static String expected(String value){require(value==null||sha(value),"expected scope SHA malformed");return value;}
    static boolean packageName(String value){return value!=null&&value.matches("[a-zA-Z][a-zA-Z0-9_]*(\\.[a-zA-Z0-9_]+)+");}

    /** Immutable UI restriction, separate from the immutable running task claim. */
    public static final class Launch {
        public final String expectedSha256,ownerSha256;
        public final boolean consumed;
        private Launch(String expected,String owner,boolean consumed){this.expectedSha256=expected;this.ownerSha256=owner;this.consumed=consumed;}
        public static Launch normal(){return new Launch(null,null,false);}
        public static Launch prefill(String owner,String expected){
            expected(expected);if(expected==null)return normal();
            require(owner!=null&&!owner.trim().isEmpty(),"scoped prefill needs exact task");
            return new Launch(expected,ownerHash(owner),false);
        }
        public static Launch restore(String expected,String owner,boolean consumed){
            expected(expected);require(expected!=null&&sha(owner),"saved scope binding malformed");
            return new Launch(expected,owner,consumed);
        }
        public String claim(String owner){
            require(!consumed,"scoped prefill already consumed; supply a fresh task");
            require(expectedSha256==null||ownerSha256.equals(ownerHash(owner)),"prefilled scoped task was edited");
            return expectedSha256;
        }
        public Launch accepted(){return expectedSha256==null?this:new Launch(expectedSha256,ownerSha256,true);}
    }

    public static final class Role {
        public final String role,packageName,apkSetSha256,observationSha256;
        public final int uid;
        public final long versionCode;
        Role(String role,Map<String,Object> fields){
            this.role=role;this.packageName=text(fields,role+"_package");
            require(packageName(packageName),"role package malformed: "+role);
            long value=integer(fields,role+"_uid");require(value>=0&&value<=Integer.MAX_VALUE,"role UID invalid");uid=(int)value;
            versionCode=integer(fields,role+"_version_code");require(versionCode>0,"role version invalid");
            apkSetSha256=digest(fields,role+"_apk_set_sha256");
            observationSha256=digest(fields,role+"_observation_sha256");
        }
    }
    public static final class Config {
        public final String qualificationId,buildIdentitySha256,runtimeConfigSha256,heptaApkSha256,launcherComponent;
        public final long heptaVersionCode;
        public final Map<String,Role> roles;
        private Config(Map<String,Object> fields){
            Set<String> keys=new HashSet<String>(Arrays.asList("schema","enabled","qualification_id","build_identity_sha256",
                    "runtime_config_sha256","hepta_apk_sha256","hepta_version_code","launcher_component"));
            for(String role:ROLES)for(String suffix:new String[]{"package","uid","version_code","apk_set_sha256","observation_sha256"})keys.add(role+"_"+suffix);
            require(keys.equals(fields.keySet()),"scope fields missing or unknown");
            require("hepta.qualification-scope.v1".equals(fields.get("schema"))&&Boolean.TRUE.equals(fields.get("enabled")),"scope schema/enabled invalid");
            qualificationId=text(fields,"qualification_id");require(qualificationId.matches("[a-zA-Z0-9][a-zA-Z0-9_-]{0,79}"),"qualification ID invalid");
            buildIdentitySha256=digest(fields,"build_identity_sha256");runtimeConfigSha256=digest(fields,"runtime_config_sha256");heptaApkSha256=digest(fields,"hepta_apk_sha256");
            heptaVersionCode=integer(fields,"hepta_version_code");require(heptaVersionCode>0,"Hepta version invalid");
            Map<String,Role> parsed=new LinkedHashMap<String,Role>();Set<String> packages=new HashSet<String>();
            for(String role:ROLES){Role r=new Role(role,fields);require(packages.add(r.packageName),"scope roles must use distinct packages");parsed.put(role,r);}
            require("com.android.settings".equals(parsed.get("settings").packageName),"Settings package differs from this qualification contract");
            require("com.android.settings.intelligence".equals(parsed.get("search").packageName),"search package differs from this qualification contract");
            require("com.motorola.cn.calculator".equals(parsed.get("calculator").packageName),"calculator package differs from this qualification contract");
            String home=parsed.get("launcher").packageName;
            require(!"org.trillionnium.hepta.local".equals(home)&&!"com.android.systemui".equals(home),"launcher is not an allowed HOME identity");
            launcherComponent=text(fields,"launcher_component");
            require(launcherComponent.startsWith(home+"/")&&launcherComponent.substring(home.length()+1).matches("[a-zA-Z0-9_.$]+"),"launcher component malformed");
            roles=Collections.unmodifiableMap(parsed);
        }
        public boolean allows(String pkg){for(Role role:roles.values())if(role.packageName.equals(pkg))return true;return false;}
        public static Config parse(byte[] bytes){
            require(bytes!=null&&bytes.length>0&&bytes.length<=MAX_CONFIG_BYTES,"scope byte bound");
            try{
                String text=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
                return new Config(new FlatJson(text).read());
            }catch(Violation error){throw error;}catch(Exception error){throw new Violation("scope UTF-8 invalid");}
        }
    }
    private static String text(Map<String,Object> values,String key){Object value=values.get(key);require(value instanceof String,"scope string required: "+key);return (String)value;}
    private static String digest(Map<String,Object> values,String key){String value=text(values,key);require(sha(value),"scope SHA invalid: "+key);return value;}
    private static long integer(Map<String,Object> values,String key){Object value=values.get(key);require(value instanceof Long,"scope integer required: "+key);return ((Long)value).longValue();}

    public static final class Window {
        public final String packageName;
        public final int windowId,type,displayId;
        public final boolean active,visible;
        public Window(String pkg,int id,int type,int display,boolean active,boolean visible){this.packageName=pkg;windowId=id;this.type=type;displayId=display;this.active=active;this.visible=visible;}
    }
    /** Sticky refusal: no wait, done, home or back can rescue a violated task. */
    public static final class Gate {
        public final Config config;
        private String refusal;
        private Map<String,Object> proof=Collections.emptyMap();
        public Gate(Config config){this.config=config;}
        public synchronized void fail(String reason){
            if(refusal==null)refusal=reason;
            Map<String,Object> denied=new LinkedHashMap<String,Object>(proof);denied.put("allowed",false);denied.put("reason",refusal);proof=Collections.unmodifiableMap(denied);
        }
        public synchronized String refusal(){return refusal;}
        public synchronized Map<String,Object> proof(){return new LinkedHashMap<String,Object>(proof);}
        public synchronized void check(String action,String target,Window window,String nodePackage,Integer nodeWindow,boolean nodeRequired){
            Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("schema","hepta.qualification-scope-check.v1");
            row.put("restricted",config!=null);row.put("action",action);row.put("target_package",target);
            row.put("fresh_root_package",window==null?null:window.packageName);row.put("fresh_root_window_id",window==null?null:Integer.valueOf(window.windowId));
            row.put("fresh_root_type",window==null?null:Integer.valueOf(window.type));row.put("fresh_root_display_id",window==null?null:Integer.valueOf(window.displayId));
            row.put("fresh_root_active",window==null?null:Boolean.valueOf(window.active));row.put("fresh_root_visible",window==null?null:Boolean.valueOf(window.visible));
            row.put("fresh_node_package",nodePackage);row.put("fresh_node_window_id",nodeWindow);row.put("node_required",nodeRequired);
            try{
                require(refusal==null,refusal==null?"":refusal);
                if(config!=null){
                    require(window!=null&&packageName(window.packageName)&&window.windowId>=0&&window.type==1&&window.displayId==0&&window.active&&window.visible,"fresh active application window unknown");
                    require(config.allows(window.packageName),"foreground package outside scope");
                    if("open".equals(action))require(config.allows(target),"open target outside scope");
                    else if(!"observe".equals(action))require(window.packageName.equals(target),"action package differs from fresh root");
                    if(nodeRequired)require(packageName(nodePackage)&&nodePackage.equals(window.packageName)&&nodeWindow!=null
                            &&nodeWindow.intValue()==window.windowId,"fresh node package/window outside scope");
                    require(!"coordinate_click".equals(action),"coordinate action has no scope-bound node");
                }
                row.put("allowed",true);row.put("reason",null);
            }catch(Violation error){fail(error.getMessage());row.put("allowed",false);row.put("reason",refusal);proof=Collections.unmodifiableMap(row);throw error;}
            proof=Collections.unmodifiableMap(row);
        }
    }

    /** Closed flat JSON only. Rejects duplicates, coercions, comments and trailing data. */
    private static final class FlatJson {
        final String s;int p;
        FlatJson(String value){s=value;}
        Map<String,Object> read(){
            Map<String,Object> out=new LinkedHashMap<String,Object>();ws();takeRequired('{');ws();
            if(!take('}'))while(true){String key=string();require(!out.containsKey(key),"duplicate scope key");ws();takeRequired(':');ws();Object value;
                if(at('"'))value=string();else if(s.startsWith("true",p)){p+=4;value=Boolean.TRUE;}else if(s.startsWith("false",p)){p+=5;value=Boolean.FALSE;}
                else{int start=p;require(p<s.length()&&s.charAt(p)>='0'&&s.charAt(p)<='9',"unsupported scope value");
                    if(take('0'))require(p==s.length()||!Character.isDigit(s.charAt(p)),"leading zero in scope integer");
                    else while(p<s.length()&&s.charAt(p)>='0'&&s.charAt(p)<='9')p++;
                    try{value=Long.valueOf(s.substring(start,p));}catch(NumberFormatException error){throw new Violation("scope integer overflow");}}
                out.put(key,value);ws();if(take('}'))break;takeRequired(',');ws();}
            ws();require(p==s.length(),"trailing scope data");return out;
        }
        String string(){takeRequired('"');StringBuilder out=new StringBuilder();boolean ended=false;
            while(p<s.length()){char c=s.charAt(p++);if(c=='"'){ended=true;break;}require(c>=32,"scope string control");
                if(c=='\\'){require(p<s.length(),"scope escape incomplete");char e=s.charAt(p++);
                    switch(e){case '"':c='"';break;case '\\':c='\\';break;case '/':c='/';break;case 'b':c='\b';break;case 'f':c='\f';break;case 'n':c='\n';break;case 'r':c='\r';break;case 't':c='\t';break;
                    case 'u':require(p+4<=s.length(),"scope unicode incomplete");int v=0;for(int i=0;i<4;i++){char h=s.charAt(p++);int d=Character.digit(h,16);require(d>=0&&h<128,"scope unicode invalid");v=(v<<4)|d;}c=(char)v;break;
                    default:throw new Violation("scope escape invalid");}}
                out.append(c);
            }
            require(ended,"scope string unterminated");String value=out.toString();
            for(int i=0;i<value.length();i++){char c=value.charAt(i);require(c!=0,"scope NUL");if(Character.isHighSurrogate(c))require(++i<value.length()&&Character.isLowSurrogate(value.charAt(i)),"scope invalid surrogate");else require(!Character.isLowSurrogate(c),"scope invalid surrogate");}
            return value;
        }
        void ws(){while(p<s.length()&&" \t\r\n".indexOf(s.charAt(p))>=0)p++;}
        boolean at(char c){return p<s.length()&&s.charAt(p)==c;}
        boolean take(char c){if(!at(c))return false;p++;return true;}
        void takeRequired(char c){require(take(c),"malformed scope JSON");}
    }
}
