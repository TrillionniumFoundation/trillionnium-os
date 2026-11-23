package org.trillionnium.hepta.background;

import java.nio.charset.StandardCharsets;
import java.util.*;

/** Actual pure policy and actual strict protocol. No Android, root or phone. */
public final class PublicOwnGroupPolicyHostTest {
    private static final String GEN="11111111-1111-4111-8111-111111111111",REQ="22222222-2222-4222-8222-222222222222";
    private static int cases,checks;
    interface Work{void run()throws Exception;}
    static void yes(boolean v){checks++;if(!v)throw new AssertionError("policy check failed");}
    static void test(String name,Work w)throws Exception{w.run();cases++;System.out.println("PASS "+name);}
    static void no(Work w)throws Exception{try{w.run();}catch(IllegalArgumentException|BrokerProtocol.Refusal expected){checks++;return;}throw new AssertionError("invalid input accepted");}
    static String hash(char c){char[] b=new char[64];Arrays.fill(b,c);return new String(b);}
    static ProfileTarget target(){return new ProfileTarget(new ProfileIdentity(10,20,0,ProfileIdentity.MANAGED),1010367,
            ProfileTarget.CTRIP,ProfileTarget.CTRIP+"/ctrip.android.view.Splash",1,Collections.singletonMap("base",hash('a')),Collections.singleton(hash('b')));}
    static PublicOwnGroupPolicy.Scope scope(ProfileTarget target){return new PublicOwnGroupPolicy.Scope(hash('c').substring(0,32),hash('d'),GEN,10123,target,1000,541000,10);}
    static PublicOwnGroupPolicy.Credentials credentials(int target,boolean showing){return new PublicOwnGroupPolicy.Credentials(0,showing,
            new PublicOwnGroupPolicy.UserState(0,0,false,false,false),new PublicOwnGroupPolicy.UserState(target,0,false,false,false));}
    static PublicOwnGroupPolicy.DisplayState display(String unique,int group){return new PublicOwnGroupPolicy.DisplayState(7,"hepta-bg-"+GEN,unique,0,"com.android.shell",7040,group,0,0,1,1,2,2);}
    static Map<Integer,String> physical(){Map<Integer,String> m=new LinkedHashMap<Integer,String>();m.put(0,hash('e'));m.put(1,hash('f'));return m;}
    static PublicOwnGroupPolicy.Readback read(PublicOwnGroupPolicy.Scope scope,String req,long now,String unique,int group,boolean showing,Map<Integer,String> physical){
        return new PublicOwnGroupPolicy.Readback(scope,req,now,now,new PublicOwnGroupPolicy.Privileges(0,0,0,0),credentials(scope.targetUserId,showing),display(unique,group),physical(physical,1));
    }
    static PublicOwnGroupPolicy.PhysicalDisplays physical(Map<Integer,String> identities,int state){
        Map<Integer,String> facts=new LinkedHashMap<Integer,String>();facts.put(0,"{\"state\":"+state+",\"rotation\":0}");facts.put(1,"{\"state\":1,\"rotation\":0}");
        return new PublicOwnGroupPolicy.PhysicalDisplays(identities,facts);
    }
    static PublicOwnGroupPolicy.AppDisplay app(long now){return new PublicOwnGroupPolicy.AppDisplay(7,"hepta-bg-"+GEN,7040,true,now,now);}
    static String[] config(PublicOwnGroupPolicy.Scope scope,ProfileTarget target){List<String> a=new ArrayList<String>(Arrays.asList("--socket","hepta-bg-"+GEN,"--owner-uid","10123","--generation",GEN,
            "--allowed-packages",target==null?"com.example.app":target.packageName,"--ttl-ms","540000","--expires-elapsed-ms","541000"));
        if(target!=null){a.add("--profile-target");a.add(target.wire());}if(scope!=null){a.add("--public-own-group-scope");a.add(scope.wire());}return a.toArray(new String[0]);}
    static String request(int version,String op,PublicOwnGroupPolicy.Scope scope,ProfileTarget target){return "{\"version\":"+version+",\"request_id\":\""+REQ+"\",\"generation\":\""+GEN+"\",\"deadline_elapsed_ms\":2000,\"op\":\""+op+"\""
            +(scope==null?"":",\"display_scope_sha256\":\""+scope.sha256+"\"")+(target==null?"":",\"target_sha256\":\""+target.sha256+"\"")+"}";}
    static BrokerProtocol.Request parse(String r)throws Exception{return BrokerProtocol.Request.parse(r.getBytes(StandardCharsets.UTF_8));}
    public static void main(String[] args)throws Exception{
        test("scope canonical wire binds complete original task and profile",()->{for(ProfileTarget t:new ProfileTarget[]{null,target()}){
            PublicOwnGroupPolicy.Scope s=scope(t),copy=PublicOwnGroupPolicy.Scope.fromWire(s.wire());yes(copy.sha256.equals(s.sha256));
            copy.requireConfig(10123,GEN,541000,t);yes(copy.targetUserId==(t==null?0:10));no(()->copy.requireConfig(10124,GEN,541000,t));
            no(()->copy.requireConfig(10123,UUID.randomUUID().toString(),541000,t));no(()->copy.requireConfig(10123,GEN,541001,t));
        }});
        test("target0 and profile10 are not interchangeable",()->{no(()->scope(null).requireConfig(10123,GEN,541000,target()));no(()->scope(target()).requireConfig(10123,GEN,541000,null));});
        test("unknown boot and malformed owner rejected",()->{no(()->new PublicOwnGroupPolicy.Scope(hash('c').substring(0,32),hash('d'),GEN,10123,null,1000,541000,-1));no(()->new PublicOwnGroupPolicy.Scope("bad",hash('d'),GEN,10123,null,1000,541000,1));});
        for(int mask=0;mask<4;mask++){final int m=mask;test("root and each actual protected permission required "+m,()->no(()->new PublicOwnGroupPolicy.Privileges(m==0?2000:0,m==1?-1:0,m==2?-1:0,m==3?-1:0)));}
        for(int user:new int[]{0,10})for(int flag=0;flag<3;flag++){final int u=user,f=flag;test("credential state blocks user "+u+" flag "+f,()->no(()->new PublicOwnGroupPolicy.UserState(u,0,f==0,f==1,f==2)));}
        test("virtual display id cannot be substituted for trust deviceId0",()->no(()->new PublicOwnGroupPolicy.UserState(10,7,false,false,false)));
        test("current foreground user must be zero",()->no(()->new PublicOwnGroupPolicy.Credentials(10,true,new PublicOwnGroupPolicy.UserState(0,0,false,false,false),new PublicOwnGroupPolicy.UserState(10,0,false,false,false))));
        for(int bad:new int[]{0,1,6272,7044,7042,7040|32}){final int flags=bad;test("actual flag mismatch "+flags,()->no(()->new PublicOwnGroupPolicy.DisplayState(7,"hepta-bg-"+GEN,"virtual:x",0,"com.android.shell",flags,2,0,0,1,1,2,2)));}
        for(int group:new int[]{0,1}){final int g=group;test("group must differ from both physical groups "+g,()->no(()->new PublicOwnGroupPolicy.DisplayState(7,"hepta-bg-"+GEN,"virtual:x",0,"com.android.shell",7040,g,0,1,1,1,2,2)));}
        test("destroy removeMode is required independently from flags",()->no(()->new PublicOwnGroupPolicy.DisplayState(7,"hepta-bg-"+GEN,"virtual:x",0,"com.android.shell",7040,2,0,0,0,1,2,2)));
        test("actual owner cannot be SystemUI or shell UID",()->{no(()->new PublicOwnGroupPolicy.DisplayState(7,"hepta-bg-"+GEN,"virtual:x",2000,"com.android.shell",7040,2,0,0,1,1,2,2));no(()->new PublicOwnGroupPolicy.DisplayState(7,"hepta-bg-"+GEN,"virtual:x",0,"com.android.systemui",7040,2,0,0,1,1,2,2));});
        test("ordinary app must read actual named public display",()->{no(()->new PublicOwnGroupPolicy.AppDisplay(0,"main",7040,true,1000,1000));no(()->new PublicOwnGroupPolicy.AppDisplay(7,"hepta-bg-"+GEN,7040,false,1000,1000));});
        test("canonical readback decoding is evidence only",()->{PublicOwnGroupPolicy.Scope s=scope(null);PublicOwnGroupPolicy.Readback p=read(s,REQ,1100,"virtual:x",2,true,physical());
            yes(PublicOwnGroupPolicy.Readback.fromWire(p.wire(),s).sha256.equals(p.sha256));Object owner=new Object();PublicOwnGroupPolicy.LiveLease lease=new PublicOwnGroupPolicy.LiveLease(owner,s);
            no(()->lease.current(owner,1100,app(1100)));lease.registerRootRpc(owner,p,0,REQ,1099,1100,app(1100));yes(lease.current(owner,1100,app(1100))==p);
            no(()->lease.current(new Object(),1100,app(1100)));yes(lease.current(owner,1100,app(1100))==p);
        });
        test("stale admission schedules only; cannot authorize effect",()->{PublicOwnGroupPolicy.Scope s=scope(null);Object owner=new Object();PublicOwnGroupPolicy.LiveLease l=new PublicOwnGroupPolicy.LiveLease(owner,s);
            PublicOwnGroupPolicy.Readback p=read(s,REQ,1100,"virtual:x",2,true,physical());l.registerRootRpc(owner,p,0,REQ,1100,1100,app(1100));
            l.requireAdmission(owner,3100);yes(l.refreshRequired(owner,3100));no(()->l.current(owner,3100,app(3100)));
            PublicOwnGroupPolicy.Readback fresh=read(s,UUID.randomUUID().toString(),3100,"virtual:x",2,true,physical());l.registerRootRpc(owner,fresh,0,fresh.requestId,3100,3100,app(3100));yes(l.current(owner,3100,app(3100))==fresh);
        });
        for(String change:new String[]{"root_peer","request_id","predates_request","future","unique","group","physical0","physical1","replay"})test("changed proof retires exact live lease "+change,()->{
            PublicOwnGroupPolicy.Scope s=scope(null);Object owner=new Object();PublicOwnGroupPolicy.LiveLease l=new PublicOwnGroupPolicy.LiveLease(owner,s);
            PublicOwnGroupPolicy.Readback old=read(s,REQ,1100,"virtual:x",2,true,physical());l.registerRootRpc(owner,old,0,REQ,1100,1100,app(1100));
            String req="replay".equals(change)?REQ:UUID.randomUUID().toString();Map<Integer,String> ph=physical();if("physical0".equals(change))ph.put(0,hash('a'));if("physical1".equals(change))ph.put(1,hash('a'));
            PublicOwnGroupPolicy.Readback p=read(s,req,1200,"unique".equals(change)?"virtual:y":"virtual:x","group".equals(change)?3:2,!"showing".equals(change),ph);
            no(()->l.registerRootRpc(owner,p,"root_peer".equals(change)?2000:0,"request_id".equals(change)?REQ:req,"predates_request".equals(change)?1201:1200,"future".equals(change)?1199:1200,app(1200)));
            no(()->l.current(owner,1200,app(1200)));no(()->l.registerRootRpc(owner,read(s,UUID.randomUUID().toString(),1300,"virtual:x",2,true,physical()),0,UUID.randomUUID().toString(),1300,1300,app(1300)));
        });
        test("user screen power rotation group and keyguard showing are observations only",()->{
            PublicOwnGroupPolicy.Scope s=scope(null);Object owner=new Object();PublicOwnGroupPolicy.LiveLease l=new PublicOwnGroupPolicy.LiveLease(owner,s);
            PublicOwnGroupPolicy.Readback initial=read(s,REQ,1100,"virtual:x",2,true,physical());l.registerRootRpc(owner,initial,0,REQ,1100,1100,app(1100));
            String request=UUID.randomUUID().toString();PublicOwnGroupPolicy.Readback next=new PublicOwnGroupPolicy.Readback(s,request,1200,1200,
                new PublicOwnGroupPolicy.Privileges(0,0,0,0),credentials(0,false),
                new PublicOwnGroupPolicy.DisplayState(7,"hepta-bg-"+GEN,"virtual:x",0,"com.android.shell",7040,2,3,4,1,1,2,2),physical(physical(),2));
            l.registerRootRpc(owner,next,0,request,1200,1200,app(1200));yes(l.current(owner,1200,app(1200))==next);
            yes(!next.physicalObservedFacts.equals(initial.physicalObservedFacts)&&next.physicalDeviceIdentities.equals(initial.physicalDeviceIdentities));
        });
        test("explicit retirement cannot be renewed by serialized receipt",()->{PublicOwnGroupPolicy.Scope s=scope(null);Object owner=new Object();PublicOwnGroupPolicy.LiveLease l=new PublicOwnGroupPolicy.LiveLease(owner,s);l.retire(owner);
            PublicOwnGroupPolicy.Readback p=read(s,REQ,1100,"virtual:x",2,true,physical());no(()->l.registerRootRpc(owner,p,0,REQ,1100,1100,app(1100)));});
        test("legacy config versions and scopes remain exact",()->{yes(BrokerProtocol.Config.parse(config(null,null)).protocolVersion()==1);yes(BrokerProtocol.Config.parse(config(null,target())).protocolVersion()==2);
            no(()->parse(request(1,"display_policy",null,null)));no(()->parse(request(2,"display_policy",null,target())));});
        test("experimental v3 and v4 bind scope config and peer owner",()->{for(ProfileTarget t:new ProfileTarget[]{null,target()}){
            PublicOwnGroupPolicy.Scope s=scope(t);BrokerProtocol.Config c=BrokerProtocol.Config.parse(config(s,t));yes(c.protocolVersion()==(t==null?3:4));
            BrokerProtocol.Request r=parse(request(c.protocolVersion(),"display_policy",s,t));r.authenticate(c,10123);no(()->r.authenticate(c,10124));
            no(()->parse(request(c.protocolVersion(),"display_policy",null,t)));no(()->parse(request(c.protocolVersion(),"display_policy",s,t).replace("}",",\"grant\":true}")));
            no(()->parse(request(c.protocolVersion(),"display_policy",s,t).replace(s.sha256,hash('0'))).authenticate(c,10123));
        }});
        test("v4 permission window adds scope without widening packages",()->{ProfileTarget t=target();PublicOwnGroupPolicy.Scope s=scope(t);String raw=request(4,"permission_window",s,t).replace("}",",\"package\":\""+t.packageName+"\",\"window_id\":14,\"task_id\":300}");
            BrokerProtocol.Request r=parse(raw);r.authenticate(BrokerProtocol.Config.parse(config(s,t)),10123);yes(r.observedTaskId==300);no(()->parse(raw.replace("\"version\":4","\"version\":3")));});
        test("legacy always-unlocked rejection remains intact",()->{Map<String,Integer> c=new LinkedHashMap<String,Integer>();c.put("FLAG_TRUSTED",128);c.put("FLAG_OWN_FOCUS",2048);c.put("FLAG_STEAL_TOP_FOCUS_DISABLED",4096);c.put("FLAG_SECURE",2);c.put("FLAG_ALWAYS_UNLOCKED",512);
            yes(BrokerProtocol.DisplayPolicy.checked(6272,c,2,2).flags==6272);no(()->BrokerProtocol.DisplayPolicy.checked(7040,c,2,2));});
        System.out.println("{\"cases\":"+cases+",\"assertions\":"+checks+",\"passed\":true,\"phone_contacted\":false}");
    }
}
