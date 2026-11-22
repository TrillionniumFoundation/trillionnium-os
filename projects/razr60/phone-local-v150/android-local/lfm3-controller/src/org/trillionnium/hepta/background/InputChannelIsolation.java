package org.trillionnium.hepta.background;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Complete raw WindowInfos facts and a read-only channel-isolation comparison.
 * Tokens are live objects supplied by the framework adapter, never strings parsed from a receipt.
 * A Match is deliberately not an input permit. No method injects or authorizes an input event.
 */
final class InputChannelIsolation {
    static final int MAX_WINDOWS=512, MAX_DISPLAYS=128, MAX_REGION_RECTS=8192;
    static final long MAX_CALLBACK_AGE_MS=2000;
    private InputChannelIsolation() {}

    static final class Refusal extends Exception {
        private static final long serialVersionUID=1L;
        final String code;
        Refusal(String code){super(code);this.code=code;}
    }
    static void need(boolean value,String code)throws Refusal{if(!value)throw new Refusal(code);}

    static final class Flags {
        static final String[] NAMES={"NO_INPUT_CHANNEL","NOT_VISIBLE","NOT_TOUCHABLE",
                "SPY","CLONE","DUPLICATE_TOUCH_TO_WALLPAPER","IS_WALLPAPER","SLIPPERY"};
        final Map<String,Integer> values;
        final int knownMask;
        Flags(Map<String,Integer> all)throws Refusal{
            need(all!=null&&!all.isEmpty()&&all.size()<=128,"INPUT_CONFIG_CONSTANTS_INCOMPLETE");
            int used=0;Map<String,Integer> copy=new LinkedHashMap<String,Integer>();
            for(Map.Entry<String,Integer> e:all.entrySet()){
                String key=e.getKey();Integer boxed=e.getValue();
                need(key!=null&&key.matches("[A-Z][A-Z0-9_]{0,95}")&&boxed!=null,"INPUT_CONFIG_CONSTANT_INVALID");
                int v=boxed.intValue();
                if("DEFAULT".equals(key)){need(v==0,"INPUT_CONFIG_DEFAULT_INVALID");copy.put(key,v);continue;}
                need(v>0&&(v&(v-1))==0&&(used&v)==0,"INPUT_CONFIG_CONSTANT_INVALID");
                used|=v;copy.put(key,v);
            }
            for(String n:NAMES)need(copy.containsKey(n),"INPUT_CONFIG_CONSTANTS_INCOMPLETE");
            knownMask=used;values=Collections.unmodifiableMap(copy);
        }
        boolean has(int config,String name){return (config&values.get(name).intValue())!=0;}
    }

    static final class DisplayFacts {
        final int id,width,height;
        private final float[] transform;
        DisplayFacts(int id,int width,int height,float[] transform)throws Refusal{
            need(id>=0&&width>=0&&height>=0&&width<=16384&&height<=16384,"INPUT_DISPLAY_FACTS_INVALID");
            this.id=id;this.width=width;this.height=height;this.transform=matrix(transform);
        }
        float[] transform(){return transform.clone();}
    }
    static final class WindowFacts {
        final Object inputToken,windowToken;
        final int displayId,uid,pid,inputConfig,layoutType,layoutFlags;
        final String packageName;
        final float alpha;
        private final int[] frame;
        private final int[][] region;
        private final float[] transform;
        WindowFacts(Object input,Object window,int display,int uid,int pid,String pkg,int config,
                int type,int flags,int[] frame,int[][] region,float[] transform,float alpha)throws Refusal{
            need(display>=0&&uid>=0&&pid>=0&&pkg!=null&&pkg.length()<=512&&pkg.indexOf('\0')<0,
                    "INPUT_WINDOW_IDENTITY_INVALID");
            need(frame!=null&&frame.length==4&&region!=null&&region.length<=MAX_REGION_RECTS,
                    "INPUT_WINDOW_GEOMETRY_INCOMPLETE");
            this.inputToken=input;this.windowToken=window;displayId=display;this.uid=uid;this.pid=pid;
            packageName=pkg;inputConfig=config;layoutType=type;layoutFlags=flags;this.frame=frame.clone();
            this.region=new int[region.length][];
            for(int i=0;i<region.length;i++){
                need(region[i]!=null&&region[i].length==4&&positive(region[i]),"INPUT_REGION_INVALID");
                this.region[i]=region[i].clone();
            }
            this.transform=matrix(transform);
            need(Float.isFinite(alpha)&&alpha>=0&&alpha<=1,"INPUT_ALPHA_INVALID");this.alpha=alpha;
        }
        int[] frame(){return frame.clone();}
        int[][] region(){int[][] out=new int[region.length][];for(int i=0;i<region.length;i++)out[i]=region[i].clone();return out;}
        float[] transform(){return transform.clone();}
    }

    static final class Census {
        final long ordinal,receivedElapsedMs,completedElapsedMs;
        final List<WindowFacts> windows;
        final List<DisplayFacts> displays;
        final Flags flags;
        final String sha256;
        final int regionRects;
        Census(long ordinal,long received,long completed,List<WindowFacts> windows,
                List<DisplayFacts> displays,Flags flags)throws Refusal{
            need(ordinal>0&&received>=0&&completed>=received,"INPUT_CALLBACK_CLOCK_INVALID");
            need(windows!=null&&!windows.isEmpty()&&windows.size()<=MAX_WINDOWS
                    &&displays!=null&&!displays.isEmpty()&&displays.size()<=MAX_DISPLAYS&&flags!=null,
                    "INPUT_CENSUS_INCOMPLETE");
            Map<Integer,DisplayFacts> unique=new LinkedHashMap<Integer,DisplayFacts>();
            for(DisplayFacts d:displays)need(d!=null&&unique.put(d.id,d)==null,"INPUT_DISPLAY_DUPLICATE");
            int count=0;
            for(WindowFacts w:windows){
                need(w!=null&&unique.containsKey(w.displayId),"INPUT_WINDOW_DISPLAY_UNKNOWN");
                need((w.inputConfig&~flags.knownMask)==0,"INPUT_WINDOW_CONFIG_UNKNOWN");
                count+=w.region.length;need(count<=MAX_REGION_RECTS,"INPUT_CENSUS_REGION_LIMIT");
                need(w.inputToken!=null||flags.has(w.inputConfig,"NO_INPUT_CHANNEL"),"INPUT_CHANNEL_UNKNOWN");
            }
            this.ordinal=ordinal;receivedElapsedMs=received;completedElapsedMs=completed;
            this.windows=Collections.unmodifiableList(new ArrayList<WindowFacts>(windows));
            this.displays=Collections.unmodifiableList(new ArrayList<DisplayFacts>(displays));
            this.flags=flags;regionRects=count;sha256=hashFacts();
        }
        private String hashFacts()throws Refusal{
            try{
                ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);
                out.writeUTF("hepta.raw-window-infos-census.v1");out.writeLong(ordinal);
                out.writeLong(receivedElapsedMs);out.writeLong(completedElapsedMs);
                out.writeInt(flags.values.size());for(Map.Entry<String,Integer> e:flags.values.entrySet()){out.writeUTF(e.getKey());out.writeInt(e.getValue());}
                out.writeInt(displays.size());for(DisplayFacts d:displays){out.writeInt(d.id);out.writeInt(d.width);out.writeInt(d.height);write(out,d.transform);}
                IdentityHashMap<Object,Integer> tokenIds=new IdentityHashMap<Object,Integer>();
                out.writeInt(windows.size());for(WindowFacts w:windows){
                    out.writeInt(tokenId(tokenIds,w.inputToken));out.writeInt(tokenId(tokenIds,w.windowToken));
                    out.writeInt(w.displayId);out.writeInt(w.uid);out.writeInt(w.pid);out.writeUTF(w.packageName);
                    out.writeInt(w.inputConfig);out.writeInt(w.layoutType);out.writeInt(w.layoutFlags);
                    write(out,w.frame);out.writeInt(w.region.length);for(int[] rect:w.region)write(out,rect);
                    write(out,w.transform);out.writeInt(Float.floatToIntBits(w.alpha));
                }
                out.flush();need(bytes.size()<=1048576,"INPUT_CENSUS_BYTE_LIMIT");
                byte[] digest=MessageDigest.getInstance("SHA-256").digest(bytes.toByteArray());
                StringBuilder s=new StringBuilder(64);for(byte b:digest)s.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return s.toString();
            }catch(Refusal e){throw e;}catch(Exception e){throw new Refusal("INPUT_CENSUS_HASH_FAILED");}
        }
    }

    static final class Expected {
        final int displayId,fullUid,userId,namespaceUserId,windowId,taskId,width,height,rotation;
        final String packageName;
        final Object axWindowToken;
        Expected(int display,int uid,int user,int namespace,int window,int task,String pkg,
                int width,int height,int rotation,Object token)throws Refusal{
            need(display>1&&user>0&&namespace>=0&&namespace!=user&&uid/100000==user
                    &&uid%100000>=10000&&uid%100000<90000&&window>=0&&task>0,
                    "INPUT_EXPECTED_OWNER_INVALID");
            need("ctrip.android.view".equals(pkg)&&token!=null&&width>0&&height>0&&width<=4096
                    &&height<=4096&&(long)width*height<=16000000&&rotation>=0&&rotation<=3,
                    "INPUT_EXPECTED_WINDOW_INVALID");
            displayId=display;fullUid=uid;userId=user;namespaceUserId=namespace;windowId=window;taskId=task;
            packageName=pkg;this.width=width;this.height=height;this.rotation=rotation;axWindowToken=token;
        }
    }
    static final class Match {
        final Census census;
        final WindowFacts target;
        final Expected expected;
        final long checkedElapsedMs;
        final int ownedWindows,ownedChannels,foreignDisplayWindows;
        private final double[] logicalFrame;
        Match(Census c,WindowFacts w,Expected e,long now,int owned,int channels,int foreign,double[] frame){
            census=c;target=w;expected=e;checkedElapsedMs=now;ownedWindows=owned;ownedChannels=channels;
            foreignDisplayWindows=foreign;logicalFrame=frame.clone();
        }
        Map<String,Object> evidence(){
            Map<String,Object> v=new LinkedHashMap<String,Object>();
            v.put("schema","hepta.input-channel-isolation-readonly.v1");
            v.put("source","raw_WindowInfosListener_callback_and_actual_accessibility_window_token");
            v.put("census_sha256",census.sha256);v.put("callback_ordinal",census.ordinal);
            v.put("callback_received_elapsed_ms",census.receivedElapsedMs);v.put("facts_copy_completed_elapsed_ms",census.completedElapsedMs);
            v.put("checked_elapsed_ms",checkedElapsedMs);v.put("window_count",census.windows.size());
            v.put("display_count",census.displays.size());v.put("region_rectangle_count",census.regionRects);
            v.put("omitted_window_count",0);v.put("owned_display_window_count",ownedWindows);
            v.put("owned_display_channel_count",ownedChannels);v.put("other_display_window_count",foreignDisplayWindows);
            v.put("target_profile_user_id",expected.userId);v.put("accessibility_namespace_user_id",expected.namespaceUserId);
            v.put("full_uid",expected.fullUid);v.put("package",expected.packageName);v.put("display_id",expected.displayId);
            v.put("accessibility_window_id",expected.windowId);v.put("observed_task_id",expected.taskId);
            v.put("display_width",expected.width);v.put("display_height",expected.height);v.put("display_rotation",expected.rotation);
            v.put("actual_window_token_match_count",1);v.put("actual_input_token_present",true);
            v.put("cross_display_input_or_window_token_aliases",0);v.put("ambiguous_owned_channel_rows",0);
            v.put("raw_frame",ints(target.frame));v.put("logical_frame",doubles(logicalFrame));
            v.put("raw_window_transform",floats(target.transform));v.put("input_config",target.inputConfig);
            v.put("input_config_constants",census.flags.values);
            v.put("global_monitor_isolation_basis","AOSP_fresh_channel_pair_and_single_display_registration");
            v.put("global_monitor_tokens_observed",false);v.put("vendor_dispatcher_qualified",false);
            v.put("privileged_post_census_mirror_excluded",false);v.put("atomic_surface_epoch_compare_and_dispatch",false);
            v.put("date_rectangle_verified",false);v.put("grants_dispatch",false);v.put("input_attempts",0);
            return Collections.unmodifiableMap(v);
        }
    }

    static Match inspect(Census c,Expected e,long now,long deadline)throws Refusal{
        need(c!=null&&e!=null&&deadline>0&&now>=c.completedElapsedMs&&now<deadline
                &&now-c.receivedElapsedMs<=MAX_CALLBACK_AGE_MS,"INPUT_CENSUS_STALE");
        DisplayFacts display=null;for(DisplayFacts d:c.displays)if(d.id==e.displayId)display=d;
        need(display!=null&&display.width==e.width&&display.height==e.height,"INPUT_DISPLAY_GEOMETRY_MISMATCH");
        WindowFacts target=null;int matches=0,owned=0,foreign=0;
        IdentityHashMap<Object,Integer> ownedInputs=new IdentityHashMap<Object,Integer>();
        IdentityHashMap<Object,Integer> ownedWindows=new IdentityHashMap<Object,Integer>();
        for(WindowFacts w:c.windows){
            if(w.displayId==e.displayId){
                owned++;
                if(w.inputToken!=null)ownedInputs.put(w.inputToken,ownedInputs.containsKey(w.inputToken)?ownedInputs.get(w.inputToken)+1:1);
                if(w.windowToken!=null)ownedWindows.put(w.windowToken,ownedWindows.containsKey(w.windowToken)?ownedWindows.get(w.windowToken)+1:1);
                need(!c.flags.has(w.inputConfig,"CLONE")&&!c.flags.has(w.inputConfig,"SPY"),"INPUT_OWNED_SPY_OR_CLONE");
                if(w.inputToken!=null&&!c.flags.has(w.inputConfig,"NOT_VISIBLE")&&!c.flags.has(w.inputConfig,"NOT_TOUCHABLE")){
                    need(w.uid==e.fullUid&&e.packageName.equals(w.packageName),"INPUT_FOREIGN_TOUCH_RECIPIENT");
                    need(w.windowToken==e.axWindowToken,"INPUT_ADDITIONAL_OWNED_TOUCH_RECIPIENT");
                }
            }else foreign++;
            if(w.windowToken==e.axWindowToken){matches++;target=w;}
        }
        need(matches==1&&target!=null,"INPUT_WINDOW_TOKEN_MATCH_NOT_UNIQUE");
        need(target.displayId==e.displayId&&target.uid==e.fullUid&&target.pid>0
                &&target.packageName.equals(e.packageName)&&target.inputToken!=null,"INPUT_WINDOW_OWNER_MISMATCH");
        need(target.inputToken!=target.windowToken,"INPUT_TOKEN_NAMESPACES_COLLIDE");
        for(Integer n:ownedInputs.values())need(n.intValue()==1,"INPUT_OWNED_CHANNEL_AMBIGUOUS");
        for(Integer n:ownedWindows.values())need(n.intValue()==1,"INPUT_OWNED_WINDOW_AMBIGUOUS");
        for(WindowFacts w:c.windows)if(w.displayId!=e.displayId){
            need(w.inputToken==null||!ownedInputs.containsKey(w.inputToken),"INPUT_CHANNEL_CROSS_DISPLAY_ALIAS");
            need(w.windowToken==null||!ownedWindows.containsKey(w.windowToken),"INPUT_WINDOW_CROSS_DISPLAY_ALIAS");
        }
        for(String name:new String[]{"NO_INPUT_CHANNEL","NOT_VISIBLE","NOT_TOUCHABLE","SPY","CLONE",
                "DUPLICATE_TOUCH_TO_WALLPAPER","IS_WALLPAPER","SLIPPERY"})
            need(!c.flags.has(target.inputConfig,name),"INPUT_TARGET_NOT_SIMPLE_TOUCH_WINDOW");
        need(target.alpha>0&&positive(target.frame)&&target.region.length>0,"INPUT_TARGET_GEOMETRY_UNAVAILABLE");
        rectilinear(display.transform);rectilinear(target.transform);
        double[] logical=mapRect(display.transform,target.frame);
        need(logical[0]>=0&&logical[1]>=0&&logical[2]<=e.width&&logical[3]<=e.height
                &&logical[0]<logical[2]&&logical[1]<logical[3],"INPUT_TARGET_OUTSIDE_OWNED_DISPLAY");
        return new Match(c,target,e,now,owned,ownedInputs.size(),foreign,logical);
    }

    /**
     * Restricts the candidate point to this live matched window. It does not
     * prove that the point represents the requested day; that is a post-effect
     * FORM observation obligation. No input or authority is created here.
     */
    static double[] calendarPoint(Match match,BrokerProtocol.CalendarDate date,long now,long deadline)throws Refusal{
        need(match!=null&&date!=null,"CALENDAR_MATCH_REQUIRED");
        Expected e=match.expected;Census c=match.census;
        need(now>=match.checkedElapsedMs&&now<deadline&&now-c.receivedElapsedMs<=MAX_CALLBACK_AGE_MS,
                "CALENDAR_MATCH_STALE");
        need(date.width==e.width&&date.height==e.height&&date.rotation==e.rotation,
                "CALENDAR_IMAGE_GEOMETRY_CHANGED");
        double[] frame=match.logicalFrame;
        need(date.left>=frame[0]&&date.top>=frame[1]&&date.right<=frame[2]&&date.bottom<=frame[3],
                "CALENDAR_RECT_OUTSIDE_MATCHED_WINDOW");
        double x=((double)date.left+date.right)/2.0,y=((double)date.top+date.bottom)/2.0;
        int hitX=(int)Math.floor(x),hitY=(int)Math.floor(y);
        DisplayFacts display=null;for(DisplayFacts d:c.displays)if(d.id==e.displayId)display=d;
        need(display!=null,"CALENDAR_DISPLAY_MISSING");
        boolean touchable=false;
        for(int[] raw:match.target.region){
            double[] logical=mapRect(display.transform,raw);
            // Conservative interior of the logical-space integer hit region.
            // No target-local coordinate conversion is applied to injected
            // points: Android's injection API already accepts logical space.
            if(hitX>=Math.ceil(logical[0])&&hitY>=Math.ceil(logical[1])
                    &&hitX<Math.floor(logical[2])&&hitY<Math.floor(logical[3]))touchable=true;
        }
        need(touchable,"CALENDAR_POINT_OUTSIDE_TOUCHABLE_REGION");
        return new double[]{x,y};
    }

    private static float[] matrix(float[] v)throws Refusal{
        need(v!=null&&v.length==9,"INPUT_TRANSFORM_INCOMPLETE");
        for(float x:v)need(Float.isFinite(x),"INPUT_TRANSFORM_NONFINITE");
        return v.clone();
    }
    private static void rectilinear(float[] v)throws Refusal{
        need(v[6]==0&&v[7]==0&&v[8]==1,"INPUT_TRANSFORM_PERSPECTIVE");
        double determinant=(double)v[0]*v[4]-(double)v[1]*v[3];
        need(determinant>0&&Double.isFinite(determinant),"INPUT_TRANSFORM_INVALID");
        need((v[1]==0&&v[3]==0&&v[0]!=0&&v[4]!=0)||(v[0]==0&&v[4]==0&&v[1]!=0&&v[3]!=0),
                "INPUT_TRANSFORM_NOT_AXIS_ALIGNED");
    }
    private static double[] mapRect(float[] m,int[] r){
        double l=Double.POSITIVE_INFINITY,t=l,rr=Double.NEGATIVE_INFINITY,b=rr;
        for(int x:new int[]{r[0],r[2]})for(int y:new int[]{r[1],r[3]}){
            double px=(double)m[0]*x+(double)m[1]*y+m[2],py=(double)m[3]*x+(double)m[4]*y+m[5];
            l=Math.min(l,px);t=Math.min(t,py);rr=Math.max(rr,px);b=Math.max(b,py);
        }return new double[]{l,t,rr,b};
    }
    private static boolean positive(int[] r){return r.length==4&&r[0]<r[2]&&r[1]<r[3];}
    private static int tokenId(IdentityHashMap<Object,Integer> ids,Object token){
        if(token==null)return 0;Integer old=ids.get(token);if(old!=null)return old.intValue();int next=ids.size()+1;ids.put(token,next);return next;
    }
    private static void write(DataOutputStream out,int[] v)throws IOException{for(int x:v)out.writeInt(x);}
    private static void write(DataOutputStream out,float[] v)throws IOException{for(float x:v)out.writeInt(Float.floatToIntBits(x));}
    private static List<Integer> ints(int[] v){List<Integer> out=new ArrayList<Integer>();for(int x:v)out.add(x);return Collections.unmodifiableList(out);}
    private static List<Float> floats(float[] v){List<Float> out=new ArrayList<Float>();for(float x:v)out.add(x);return Collections.unmodifiableList(out);}
    private static List<Double> doubles(double[] v){List<Double> out=new ArrayList<Double>();for(double x:v)out.add(x);return Collections.unmodifiableList(out);}
}
