package org.trillionnium.hepta.background;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Authored synthetic default and optional exact private dump replay; all TaskInfo fixtures are synthetic. */
public final class ProfilePermissionTransientHostTest {
    static final String HOME="ctrip.android.view/ctrip.android.publicproduct.home.view.CtripHomeActivity";
    static final String PC=ProfilePermissionTransient.COMPONENT;
    static int checks,cases,displayId,rootId,leafId;
    static String permissionRecord,targetRecord,leafRecord;
    static Matcher unique(String regex,String dump){
        Matcher first=Pattern.compile(regex,Pattern.MULTILINE).matcher(dump);
        yes(first.find(),"fixture shape missing");
        Matcher all=Pattern.compile(regex,Pattern.MULTILINE).matcher(dump);
        yes(all.find()&&!all.find(),"fixture shape is ambiguous");return first;
    }
    // Test metadata only. Production independently verifies the complete, unmodified fixture.
    static void fixtureShape(String dump){
        Matcher pc=unique("^ +\\* Hist  #1: ActivityRecord\\{([^\\s{}]+) u10 "
                +Pattern.quote(ProfilePermissionTransient.PACKAGE+"/.permission.ui.GrantPermissionsActivity")
                +" t([0-9]+)\\}$",dump);
        permissionRecord=pc.group(1);leafId=Integer.parseInt(pc.group(2));
        Matcher task=unique("^ +\\* Task\\{([^\\s{}]+) #"+leafId+" [^{}\\r\\n]*rootTaskId=([0-9]+) [^{}\\r\\n]*\\}$",dump.substring(0,dump.indexOf("ActivityTaskSupervisor state:")));
        leafRecord=task.group(1);rootId=Integer.parseInt(task.group(2));
        Matcher result=unique("^ +resultTo=ActivityRecord\\{([^\\s{}]+) u10 "+Pattern.quote(HOME)+" t"+leafId
                +"\\} resultWho=@android:requestPermissions: resultCode=[0-9]+$",dump);
        targetRecord=result.group(1);displayId=-1;
        Matcher displays=Pattern.compile("^Display #([0-9]+) ",Pattern.MULTILINE).matcher(dump);
        while(displays.find()&&displays.start()<pc.start())displayId=Integer.parseInt(displays.group(1));
        yes(displayId>0,"fixture display missing");
    }
    interface Work{void run()throws Exception;}
    static void yes(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    static void refused(Work work)throws Exception{
        try{work.run();throw new AssertionError("unproved identity accepted");}
        catch(ProfileTaskPolicy.Refusal expected){checks++;}
    }
    static void test(String name,Work work)throws Exception{work.run();cases++;System.out.println("PASS "+name);}
    static ProfileTarget target(){return ProfileBrokerHostTest.target(10,1010367);}
    static ProfilePermissionTransient.Authority authority()throws Exception{
        return new ProfilePermissionTransient.Authority(10,1010335,ProfilePermissionTransient.PACKAGE,
                ProfilePermissionTransient.APK,ProfilePermissionTransient.APK_SHA,ProfilePermissionTransient.SIGNER,
                330000000,true,true,true,true);
    }
    static BackgroundOwnedSingleTask.Task root(){return new BackgroundOwnedSingleTask.Task(rootId,displayId,0,-1,0,
            1010335,2,new Object(),Collections.singletonList(new Object()),null,HOME,PC,null,null,true,true);}
    static BackgroundOwnedSingleTask.Task leaf(){return new BackgroundOwnedSingleTask.Task(leafId,displayId,10,rootId,
            1010367,1010335,2,new Object(),Collections.singletonList(new Object()),ProfileBrokerHostTest.SPLASH,
            HOME,PC,ProfileBrokerHostTest.SPLASH,null,true,true);}
    static BackgroundOwnedSingleTask.Task changed(BackgroundOwnedSingleTask.Task t,Object token,List<Object> cookies,
            int user,int parent,String base,String top,int topUid){
        return new BackgroundOwnedSingleTask.Task(t.id,t.display,user,parent,t.uid,topUid,t.activities,
                token,cookies,t.intentComponent,base,top,t.real,t.orig,t.running,t.visible);
    }
    static ProfilePermissionTransient.Proof verify(String dump)throws Exception{
        return ProfilePermissionTransient.verify(dump,target(),root(),leaf(),authority(),1000,1001);
    }
    // Authored lifecycle variant. It models the observed finishing-tail shape;
    // the TaskInfo counts and tokens remain synthetic, not historical phone evidence.
    static String finishingSplashTail(String dump){
        String permission="* Hist  #1: ActivityRecord{"+permissionRecord+" u10 ";
        String home="* Hist  #0: ActivityRecord{"+targetRecord+" u10 ";
        yes(dump.contains(permission)&&dump.contains(home),"two-record fixture shape changed");
        String expanded=dump.replace(permission,"* Hist  #2: ActivityRecord{"+permissionRecord+" u10 ")
                .replace(home,"* Hist  #1: ActivityRecord{"+targetRecord+" u10 ");
        int hierarchyEnd=expanded.indexOf("\nActivityTaskSupervisor state:");
        yes(hierarchyEnd>0,"fixture supervisor boundary missing");
        Matcher row=unique("^ +\\* Task\\{"+Pattern.quote(leafRecord)+" #"+leafId+" [^{}\\r\\n]+\\}$",
                expanded.substring(0,hierarchyEnd));
        yes(row.group().contains("sz=2"),"fixture raw task size changed");
        expanded=expanded.substring(0,row.start())+row.group().replace("sz=2","sz=3")+expanded.substring(row.end());
        int start=expanded.indexOf("* Hist  #1: ActivityRecord{"+targetRecord+" u10 ");
        int end=expanded.indexOf("\nActivityTaskSupervisor state:",start);
        int nextDisplay=expanded.indexOf("\nDisplay #",start);
        yes(end>start,"fixture supervisor boundary missing");
        if(nextDisplay>=0&&nextDisplay<end)end=nextDisplay;
        String tail="\n      * Hist  #0: ActivityRecord{finishing_splash u10 "
                +ProfileBrokerHostTest.SPLASH+" t"+leafId+" f}}\n"
                +"        packageName=ctrip.android.view processName=ctrip.android.view\n"
                +"        rootOfTask=false task=Task{"+leafRecord+" #"+leafId+" type=undefined A=1010367:ctrip.android.view}\n"
                +"        app=ProcessRecord{finishing_process 2002:ctrip.android.view/u10a367}\n"
                +"        state=STOPPING delayedResume=false finishing=true\n";
        return expanded.substring(0,end)+tail+expanded.substring(end);
    }
    static BackgroundOwnedSingleTask.Task activityCount(BackgroundOwnedSingleTask.Task t,int count){
        return new BackgroundOwnedSingleTask.Task(t.id,t.display,t.user,t.parent,t.uid,t.topUid,count,
                t.token,t.cookies,t.intentComponent,t.base,t.top,t.real,t.orig,t.running,t.visible);
    }
    static final class Adapter implements ProfileOwnedTask.Platform {
        final ProfileBrokerHostTest.Fake f=new ProfileBrokerHostTest.Fake();
        final String original;
        boolean permission,stale,wrongCaller,unavailable;int proofs;
        Adapter(String original){this.original=original;}
        @Override public ProfileTarget recheck(boolean ready){return f.actual;}
        @Override public void guard()throws Exception{f.guard();}
        @Override public long now(){return f.now;}
        @Override public Object newCookie(){return f.newCookie();}
        @Override public ProfileTaskPolicy.Snapshot snapshot()throws Exception{return f.snapshot();}
        @Override public ProfileTaskPolicy.Recents recents()throws Exception{return f.recents();}
        BackgroundOwnedSingleTask.Task rootRow(){
            BackgroundOwnedSingleTask.Task t=f.rootRow();
            if(!permission||!f.app)return t;
            return new BackgroundOwnedSingleTask.Task(t.id,t.display,t.user,t.parent,t.uid,1010335,2,t.token,t.cookies,
                    null,HOME,PC,null,null,true,true);
        }
        BackgroundOwnedSingleTask.Task leafRow(){
            BackgroundOwnedSingleTask.Task t=f.leafRow();
            if(!permission)return t;
            return new BackgroundOwnedSingleTask.Task(t.id,t.display,t.user,t.parent,t.uid,1010335,2,t.token,t.cookies,
                    t.intentComponent,f.wrongBase?t.base:HOME,PC,t.real,t.orig,true,true);
        }
        @Override public List<BackgroundOwnedSingleTask.Task> roots(){return f.root?Collections.singletonList(rootRow()):Collections.emptyList();}
        @Override public List<BackgroundOwnedSingleTask.Task> children(Object token){
            yes(token.equals(f.rootToken),"arbitrary root");
            if(f.extraChild)return f.children(token);
            return f.app?Collections.singletonList(leafRow()):Collections.emptyList();
        }
        @Override public void createRoot(Object cookie){f.createRoot(cookie);}
        @Override public void bindRoot(Object token,Object cookie){f.bindRoot(token,cookie);}
        @Override public void removeLeaf(Object token)throws Exception{f.removeLeaf(token);}
        @Override public boolean deleteRoot(Object token)throws Exception{return f.deleteRoot(token);}
        @Override public void pause(){f.pause();}
        @Override public ProfilePermissionTransient.Proof permissionTransient(BackgroundOwnedSingleTask.Task r,
                BackgroundOwnedSingleTask.Task l)throws Exception{
            proofs++;
            if(unavailable)return null;
            // Explicit ID remapping for coordinator fixtures; original is separately tested unchanged.
            String dump=original.replace("Display #"+displayId+" ","Display #7 ").replace("#"+rootId+" ","#200 ")
                    .replace("rootTaskId="+rootId+" ","rootTaskId=200 ").replace("#"+leafId+" ","#300 ")
                    .replace("t"+leafId+"}","t300}").replace("t"+leafId+" f}","t300 f}");
            if(wrongCaller)dump=dump.replace("launchedFromUid=1010367 launchedFromPackage=ctrip.android.view","launchedFromUid=10367 launchedFromPackage=ctrip.android.view");
            ProfilePermissionTransient.Proof proof=ProfilePermissionTransient.verify(dump,target(),r,l,authority(),f.now,f.now);
            if(stale)f.now+=2001;return proof;
        }
        ProfileOwnedTask start(boolean observe)throws Exception{
            ProfileOwnedTask owned=new ProfileOwnedTask(this,target(),ProfileBrokerHostTest.GEN,ProfileBrokerHostTest.REQUEST,7);
            owned.prepare();owned.beforeDispatch();f.launch();owned.accepted(0);
            if(observe)yes(owned.observe(),"ordinary target observation missing");return owned;
        }
    }
    public static void main(String[] args)throws Exception{
        if(args.length!=2)throw new IllegalArgumentException("fixture and explicit synthetic/actual kind required");
        final String fixtureKind=args[1];
        byte[] raw=Files.readAllBytes(Paths.get(args[0]));
        final String digest=ProfileIdentity.sha(raw);
        if("synthetic".equals(fixtureKind))yes(raw.length==2306&&digest.equals("7f8adcb158486f74a1ebe342e54902b9fc7550ed7b0dd7bf11b36d1d97ab63f0"),"authored synthetic fixture differs");
        else if("actual".equals(fixtureKind))yes(raw.length==91980&&digest.equals("6e945458e4af25724f189ff477ebb4ab19a58099762d3d6827c3d42728c4d2fb"),"private actual bytes differ");
        else throw new IllegalArgumentException("unknown fixture kind");
        final String dump=new String(raw,StandardCharsets.UTF_8);fixtureShape(dump);
        test(fixtureKind+" complete chain is verified without a business window",()->{
            Map<String,Object> e=verify(dump).evidence();
            yes(Boolean.FALSE.equals(e.get("business_observation_allowed")),"business authority granted");
            yes(Boolean.FALSE.equals(e.get("permission_input_allowed")),"input authority granted");
            yes(e.get("leaf_task_id").equals(leafId)&&e.get("permission_uid").equals(1010335),"identity differs");
        });
        test("caller action resultTo and full user negatives",()->{
            String[][] changes={{"launchedFromUid=1010367 launchedFromPackage=ctrip.android.view","launchedFromUid=10367 launchedFromPackage=ctrip.android.view"},
                {"act=android.content.pm.action.REQUEST_PERMISSIONS","act=android.settings.SETTINGS"},
                {"resultTo=ActivityRecord{"+targetRecord,"resultTo=ActivityRecord{wrong_record"},
                {"resultWho=@android:requestPermissions:","resultWho=other:"},
                {permissionRecord+" u10 com.android.permissioncontroller",permissionRecord+" u0 com.android.permissioncontroller"},
                {"com.android.permissioncontroller/u10a335}","com.android.permissioncontroller/u0a335}"},
                {"rootOfTask=true task=Task{"+leafRecord,"rootOfTask=false task=Task{"+leafRecord},
                {"A=1010367:ctrip.android.view","A=10367:ctrip.android.view"},
                {"baseDir=/apex/com.android.permission/","baseDir=/data/app/com.android.permission/"}};
            for(String[] pair:changes){yes(dump.contains(pair[0]),"fixture absent");refused(()->verify(dump.replace(pair[0],pair[1])));}
        });
        test("mixed chain changed base leaf and incomplete dump rejected",()->{
            refused(()->verify(dump.replace("ctrip.android.view/ctrip.android.publicproduct.home.view.CtripHomeActivity","foreign.app/.Main")));
            refused(()->verify(dump.replace("t"+leafId+"}","t"+(leafId+1)+"}")));
            refused(()->verify(dump.replace("mCreatedByOrganizer=true","mCreatedByOrganizer=false")));
            refused(()->verify(dump.replace("ActivityTaskSupervisor state:","missing end:")));
        });
        test("OEM profile activity on main is never this owned transient",()->{
            String extra="\n  * Task{foreign #987654 type=standard U=10 visible=true sz=1}\n"
                    +"    * Hist  #0: ActivityRecord{foreign u10 com.motorola.deviceguard/.permission.activity.ClipboardDialogActivity t987654}\n";
            refused(()->verify(dump.replace("Display #0 (activities from top to bottom):","Display #0 (activities from top to bottom):"+extra)));
        });
        test("exact finishing and exiting suffixes remain in complete hierarchy",()->{
            for(String suffix:new String[]{""," f}"," isExiting"," f} isExiting"}){
                String extra="\n  * Task{other #987655 type=standard U=0 visible=false sz=1}\n"
                        +"    * Hist  #0: ActivityRecord{other u0 com.example.viewer/.Main t987655"+suffix+"}\n";
                verify(dump.replace("Display #0 (activities from top to bottom):","Display #0 (activities from top to bottom):"+extra));checks++;
            }
            for(String suffix:new String[]{" f"," f}}"," isExiting f}"," unknown"," f} isExiting extra"}){
                String extra="\n  * Task{other #987655 type=standard U=0 visible=false sz=1}\n"
                        +"    * Hist  #0: ActivityRecord{other u0 com.example.viewer/.Main t987655"+suffix+"}\n";
                refused(()->verify(dump.replace("Display #0 (activities from top to bottom):","Display #0 (activities from top to bottom):"+extra)));
            }
        });
        test("trusted system identity cannot be replaced by package name",()->{
            refused(()->new ProfilePermissionTransient.Authority(0,10335,ProfilePermissionTransient.PACKAGE,ProfilePermissionTransient.APK,ProfilePermissionTransient.APK_SHA,ProfilePermissionTransient.SIGNER,330000000,true,true,true,true));
            refused(()->new ProfilePermissionTransient.Authority(10,1010335,ProfilePermissionTransient.PACKAGE,ProfilePermissionTransient.APK,ProfilePermissionTransient.APK_SHA,ProfileBrokerHostTest.repeat('0'),330000000,true,true,true,true));
            refused(()->new ProfilePermissionTransient.Authority(10,1010335,ProfilePermissionTransient.PACKAGE,ProfilePermissionTransient.APK,ProfilePermissionTransient.APK_SHA,ProfilePermissionTransient.SIGNER,330000000,false,true,true,true));
            refused(()->new ProfilePermissionTransient.Authority(10,1010335,ProfilePermissionTransient.PACKAGE,ProfilePermissionTransient.APK,ProfilePermissionTransient.APK_SHA,ProfilePermissionTransient.SIGNER,330000000,true,false,true,true));
        });
        test("proof is bound to exact tokens cookies user and time",()->{
            BackgroundOwnedSingleTask.Task r=root(),l=leaf();ProfilePermissionTransient.Proof p=ProfilePermissionTransient.verify(dump,target(),r,l,authority(),1000,1001);
            p.requireMatches(target(),r,l,1002);
            refused(()->p.requireMatches(target(),r,changed(l,new Object(),l.cookies,l.user,l.parent,l.base,l.top,l.topUid),1002));
            refused(()->p.requireMatches(target(),r,changed(l,l.token,Collections.singletonList(new Object()),l.user,l.parent,l.base,l.top,l.topUid),1002));
            BackgroundOwnedSingleTask.Task noCookie=changed(l,l.token,Collections.emptyList(),l.user,l.parent,l.base,l.top,l.topUid);
            refused(()->p.requireMatches(target(),r,noCookie,1002));
            ProfilePermissionTransient.Proof fresh=ProfilePermissionTransient.verify(dump,target(),r,noCookie,authority(),1002,1003);
            fresh.requireMatches(target(),r,noCookie,1004);checks++;
            refused(()->p.requireMatches(target(),r,changed(l,l.token,l.cookies,0,l.parent,l.base,l.top,l.topUid),1002));
            refused(()->p.requireMatches(target(),r,l,3001));
            yes(ProfilePermissionTransient.Proof.class.getConstructors().length==0,"public proof reconstruction exists");
        });
        test("observe/window refuse PC while normal owned cleanup succeeds",()->{
            for(boolean loseCookie:new boolean[]{false,true}){
                Adapter a=new Adapter(dump);Object binder=new Object();
                a.f.leafToken=new ProfileBrokerHostTest.TaskToken(binder);
                ProfileOwnedTask p=a.start(true);String retained=(String)p.evidence().get("leaf_token_id");
                a.f.leafToken=new ProfileBrokerHostTest.TaskToken(binder);a.f.wrongCookie=loseCookie;a.permission=true;
                ProfileBrokerHostTest.reject("PROFILE_PERMISSION_SETUP_REQUIRED",()->p.observe());
                ProfileBrokerHostTest.reject("PROFILE_PERMISSION_SETUP_REQUIRED",()->p.window(4,300,2000));
                Map<String,Object> detail=p.lastLeafValidation();
                yes("retained_leaf".equals(detail.get("phase"))&&Boolean.TRUE.equals(detail.get("retirement_only")),"retained PC diagnostic missing");
                yes(Boolean.FALSE.equals(((Map<?,?>)detail.get("checks")).get("top_package_matches"))
                        &&Boolean.FALSE.equals(detail.get("business_observation_allowed")),"PC became business authority");
                yes(retained.equals(p.evidence().get("leaf_token_id")),"permission transition re-claimed leaf");
                p.retire(2400);yes(p.cleanupKnown(),"verified transient retained custody");
                yes(a.f.mutations.equals(Arrays.asList("create","bind","remove_leaf","delete_root")),"unexpected mutation");
            }
        });
        test("immediate first observation permission retains positive ownership",()->{
            Adapter a=new Adapter(dump);ProfileOwnedTask p=a.start(false);a.permission=true;
            ProfileBrokerHostTest.reject("PROFILE_PERMISSION_SETUP_REQUIRED",()->p.observe());
            yes("first_claim".equals(p.lastLeafValidation().get("phase"))
                    &&Boolean.TRUE.equals(p.lastLeafValidation().get("launch_cookie_present")),"first PC cookie claim missing");
            String retained=(String)p.evidence().get("leaf_token_id");a.f.wrongCookie=true;
            ProfileBrokerHostTest.reject("PROFILE_PERMISSION_SETUP_REQUIRED",()->p.observe());
            a.permission=false;yes(p.observe(),"same leaf could not return to ordinary business top");
            yes(retained.equals(p.evidence().get("leaf_token_id")),"PC to business transition replaced authority");
            a.permission=true;
            p.retire(2400);yes(p.cleanupKnown(),"fresh cookie-bound transient cannot retire");
        });
        test("cancelled task still permits evidence and owned retirement",()->{
            Adapter a=new Adapter(dump);ProfileOwnedTask p=a.start(true);a.permission=true;a.f.cancel=true;a.f.wrongCookie=true;
            p.retire(2400);yes(p.cleanupKnown(),"active-input guard prevented cleanup");
        });
        test("first PC claim requires cookie and retained identities never re-claim",()->{
            Adapter first=new Adapter(dump);ProfileOwnedTask unclaimed=first.start(false);
            first.permission=true;first.f.wrongCookie=true;
            ProfileBrokerHostTest.reject("PROFILE_NEW_LEAF_NOT_PROVEN",()->unclaimed.observe());
            yes(unclaimed.evidence().get("leaf_task_id")==null,"cookie-free first PC claimed");
            ProfileBrokerHostTest.reject("PROFILE_NEW_LEAF_NOT_PROVEN",()->unclaimed.retire(2400));
            yes(first.proofs==0&&!first.f.mutations.contains("remove_leaf"),"cookie-free first PC mutated");
            for(int kind=0;kind<12;kind++){
                Adapter a=new Adapter(dump);ProfileOwnedTask p=a.start(true);a.permission=true;a.f.wrongCookie=true;
                Map<String,Object> previous=p.lastLeafValidation();a.f.now+=5;
                if(kind==0)a.f.leafToken=new Object();
                else if(kind==1)a.f.rootCookie=new Object();
                else if(kind==2)a.f.rootToken=new Object();
                else if(kind==3)a.f.leafId=302;
                else if(kind==4)a.f.wrongUser=true;
                else if(kind==5)a.f.wrongParent=true;
                else if(kind==6)a.f.wrongDisplay=true;
                else if(kind==7)a.f.wrongUid=true;
                else if(kind==8)a.f.wrongIntent=true;
                else if(kind==9)a.f.wrongBase=true;
                else if(kind==10)a.f.wrongReal=true;
                else a.f.wrongOrig=true;
                refused(()->p.retire(2400));yes(a.proofs==0&&!a.f.mutations.contains("remove_leaf")&&!p.cleanupKnown(),"unowned leaf mutated");
                yes(p.lastLeafValidation()==previous,"early-refusal diagnostic scope unexpectedly changed");
            }
            Adapter replacement=new Adapter(dump);ProfileOwnedTask retained=replacement.start(true);
            replacement.f.app=false;
            ProfileBrokerHostTest.reject("PROFILE_OWNED_LEAF_DISAPPEARED",()->retained.observe());
            replacement.f.app=true;replacement.f.leafId=302;replacement.f.leafToken=new Object();replacement.permission=true;
            ProfileBrokerHostTest.reject("PROFILE_LEAF_TOKEN_CHANGED",()->retained.observe());
            ProfileBrokerHostTest.reject("PROFILE_LEAF_TOKEN_CHANGED",()->retained.retire(2400));
            yes(Integer.valueOf(300).equals(retained.evidence().get("leaf_task_id"))
                    &&replacement.proofs==0&&!replacement.f.mutations.contains("remove_leaf"),"replacement PC re-claimed");
        });
        test("unavailable stale caller or incomplete scope never permit retirement",()->{
            for(boolean stale:new boolean[]{false,true}){
                Adapter a=new Adapter(dump);ProfileOwnedTask p=a.start(true);a.permission=true;a.stale=stale;a.wrongCaller=!stale;
                refused(()->p.retire(5000));yes(!a.f.mutations.contains("remove_leaf")&&!p.cleanupKnown(),"unproved transient removed");
            }
            for(boolean wasClaimed:new boolean[]{false,true}){
                Adapter a=new Adapter(dump);ProfileOwnedTask p=a.start(wasClaimed);a.permission=true;a.unavailable=true;
                Map<String,Object> previous=p.lastLeafValidation();Object retained=p.evidence().get("leaf_token_id");a.f.now+=5;
                ProfileBrokerHostTest.reject("PROFILE_PERMISSION_PROOF_UNAVAILABLE",()->p.observe());
                yes(Objects.equals(retained,p.evidence().get("leaf_token_id")),"unavailable proof claimed/replaced a leaf");
                ProfileBrokerHostTest.reject("PROFILE_PERMISSION_PROOF_UNAVAILABLE",()->p.retire(2400));
                yes(p.lastLeafValidation()==previous&&!a.f.mutations.contains("remove_leaf")&&!p.cleanupKnown(),"unavailable proof became authority");
            }
            Adapter foreignTop=new Adapter(dump);ProfileOwnedTask ordinary=foreignTop.start(true);
            foreignTop.f.wrongCookie=true;foreignTop.f.foreignTop=true;
            ProfileBrokerHostTest.reject("PROFILE_NEW_LEAF_NOT_PROVEN",()->ordinary.retire(2400));
            yes(foreignTop.proofs==0&&Boolean.FALSE.equals(((Map<?,?>)ordinary.lastLeafValidation().get("checks")).get("top_package_matches")),"ordinary foreign-top contract changed");
            for(int kind=0;kind<4;kind++){
                Adapter a=new Adapter(dump);ProfileOwnedTask p=a.start(true);a.permission=true;a.f.wrongCookie=true;
                if(kind==0)a.f.foreign=true;
                else if(kind==1)a.f.initialProfileRecent=true;
                else if(kind==2)a.f.extraChild=true;
                else a.f.globalMissingLeaf=true;
                refused(()->p.retire(2400));yes(!a.f.mutations.contains("remove_leaf")&&!p.cleanupKnown(),"foreign/incomplete scope removed");
            }
        });
        test("finishing Splash stays in raw proof while live Home supplies TaskInfo base",()->{
            String expanded=finishingSplashTail(dump);
            Map<String,Object> e=verify(expanded).evidence();
            yes(e.get("leaf_task_id").equals(leafId),"finishing-tail proof changed leaf");
            yes(Boolean.FALSE.equals(e.get("business_observation_allowed"))
                    &&Boolean.FALSE.equals(e.get("permission_input_allowed")),"finishing-tail proof gained authority");
            ProfileBrokerHostTest.reject("PROFILE_PERMISSION_CHAIN_INCOMPLETE",()->
                    ProfilePermissionTransient.verify(expanded,target(),root(),activityCount(leaf(),3),authority(),1000,1001));
        });
        test("finishing raw records retain foreign user UID token ordinal and root checks",()->{
            String expanded=finishingSplashTail(dump);
            String rootLine="rootOfTask=false task=Task{"+leafRecord+" #"+leafId
                    +" type=undefined A=1010367:ctrip.android.view}\n        app=ProcessRecord{finishing_process";
            String[][] changes={
                {"finishing_splash u10 ctrip.android.view/","finishing_splash u10 foreign.app/"},
                {"finishing_splash u10 ","finishing_splash u0 "},
                {"finishing_process 2002:ctrip.android.view/u10a367}","finishing_process 2002:ctrip.android.view/u10a368}"},
                {"ActivityRecord{finishing_splash ","ActivityRecord{"+targetRecord+" "},
                {"* Hist  #0: ActivityRecord{finishing_splash ","* Hist  #1: ActivityRecord{finishing_splash "},
                {"finishing_splash u10 "+ProfileBrokerHostTest.SPLASH+" t"+leafId+" f}}",
                 "finishing_splash u10 "+ProfileBrokerHostTest.SPLASH+" t"+(leafId+1)+" f}}"},
                {rootLine,rootLine.replace("rootOfTask=false","rootOfTask=true")},
                {"* Hist  #1: ActivityRecord{"+targetRecord+" u10 "+HOME,
                 "* Hist  #1: ActivityRecord{"+targetRecord+" u10 foreign.app/.Main"}};
            for(String[] pair:changes){
                yes(expanded.contains(pair[0]),"finishing-tail negative fixture absent");
                refused(()->verify(expanded.replace(pair[0],pair[1])));
            }
        });
        test("new permission top still refuses INITIALIZING or absent process",()->{
            String expanded=finishingSplashTail(dump);
            String initializing=expanded.replace("state=RESUMED delayedResume=false finishing=false",
                    "state=INITIALIZING delayedResume=false finishing=false");
            yes(!initializing.equals(expanded),"permission state fixture absent");
            ProfileBrokerHostTest.reject("PROFILE_PERMISSION_ACTIVITY_IDENTITY_UNPROVEN",()->verify(initializing));
            String noProcess=expanded.replaceAll("app=ProcessRecord\\{[^\\r\\n{}]+:com\\.android\\.permissioncontroller/u10a335\\}","app=null");
            yes(!noProcess.equals(expanded),"permission process fixture absent");
            ProfileBrokerHostTest.reject("PROFILE_PERMISSION_PROCESS_UNPROVEN",()->verify(noProcess));
        });
        test("finishing-tail permission proof preserves observe window and retirement boundaries",()->{
            Adapter a=new Adapter(finishingSplashTail(dump));ProfileOwnedTask p=a.start(true);
            String retained=(String)p.evidence().get("leaf_token_id");a.permission=true;
            ProfileBrokerHostTest.reject("PROFILE_PERMISSION_SETUP_REQUIRED",()->p.observe());
            ProfileBrokerHostTest.reject("PROFILE_PERMISSION_SETUP_REQUIRED",()->p.window(4,300,2000));
            yes(retained.equals(p.evidence().get("leaf_token_id")),"finishing-tail transition re-claimed leaf");
            yes(Boolean.FALSE.equals(p.lastLeafValidation().get("business_observation_allowed"))
                    &&Boolean.FALSE.equals(p.lastLeafValidation().get("permission_input_allowed")),"finishing tail gained action authority");
            p.retire(2400);yes(p.cleanupKnown(),"finishing-tail owned retirement failed");
            yes(a.f.mutations.equals(Arrays.asList("create","bind","remove_leaf","delete_root")),"finishing-tail proof added mutation");
        });
        System.out.println("{\"schema\":\"hepta.profile-permission-transient-host-tests.v1\",\"passed\":true,\"cases\":"+cases+",\"assertions\":"+checks+",\"fixture_kind\":\""+fixtureKind+"\",\"fixture_sha256\":\""+digest+"\",\"taskinfo_fixtures_synthetic\":true,\"phone_contacted\":false,\"android_build\":false}");
    }
}
