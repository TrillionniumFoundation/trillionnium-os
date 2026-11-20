package org.trillionnium.hepta.background;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/** A permission-initialization observation of the actual Start-button owner.
 * A serialized locator is never task/input authority. The broker must bind it
 * to its authenticated socket peer and retain a real, freshly read task token. */
public final class PublicPermissionControllerUi {
    public static final String COMPONENT="org.trillionnium.hepta.local/org.trillionnium.hepta.local.MainActivity";
    private static final String LOCATOR="hepta.main-activity-start-locator.v1";
    private static final long MAX_START_AGE_MS=15000;
    private PublicPermissionControllerUi(){}
    private static void need(boolean ok,String code){if(!ok)throw new IllegalArgumentException(code);}

    public static final class Locator {
        public final int uid,pid,task,display;
        public final long captured;
        public final String ownerSha256;
        private Locator(int uid,int pid,int task,int display,long captured,String owner){
            need(uid>=10000&&uid<90000&&pid>0&&task>0&&(display==0||display==1)
                    &&captured>=0&&ProfileIdentity.hash(owner),"CONTROLLER_UI_LOCATOR_INVALID");
            this.uid=uid;this.pid=pid;this.task=task;this.display=display;this.captured=captured;ownerSha256=owner;
        }
        public String wire(){return LOCATOR+"|main_activity_user_button|"+uid+"|"+pid+"|"+task+"|"+display+"|"+captured+"|"+ownerSha256;}
        public static Locator fromWire(String wire){
            need(wire!=null&&wire.length()<=320,"CONTROLLER_UI_LOCATOR_INVALID");
            String[] p=wire.split("\\|",-1);
            need(p.length==8&&LOCATOR.equals(p[0])&&"main_activity_user_button".equals(p[1]),"CONTROLLER_UI_LOCATOR_SOURCE");
            for(int i=2;i<=6;i++)need(p[i].matches("0|[1-9][0-9]*"),"CONTROLLER_UI_LOCATOR_INTEGER");
            try{
                Locator out=new Locator(Integer.parseInt(p[2]),Integer.parseInt(p[3]),Integer.parseInt(p[4]),Integer.parseInt(p[5]),Long.parseLong(p[6]),p[7]);
                need(out.wire().equals(wire),"CONTROLLER_UI_LOCATOR_NONCANONICAL");return out;
            }catch(NumberFormatException bad){throw new IllegalArgumentException("CONTROLLER_UI_LOCATOR_INTEGER",bad);}
        }
    }
    /** Called only after the app has checked its real focused MainActivity on
     * the main thread. The broker still treats this result solely as a hint. */
    public static Locator fromMainActivityButton(int uid,int pid,int task,int display,long captured,String ownerSha256){
        return new Locator(uid,pid,task,display,captured,ownerSha256);
    }

    /** Broker copies these values from its already authenticated live scope. */
    public static final class Session {
        final String sha256,generation,ownerSha256;
        final int appUid,targetUserId;
        final long createdElapsedMs,expiresElapsedMs;
        public Session(String scopeSha,String generation,String owner,int uid,int targetUser,long created,long expires){
            need(ProfileIdentity.hash(scopeSha)&&ProfileIdentity.uuid(generation)&&ProfileIdentity.hash(owner)
                    &&uid>=10000&&uid<90000&&targetUser==10&&created>=0&&expires>created,"CONTROLLER_UI_SESSION_INVALID");
            sha256=scopeSha;this.generation=generation;ownerSha256=owner;appUid=uid;targetUserId=targetUser;
            createdElapsedMs=created;expiresElapsedMs=expires;
        }
    }
    /** Complete fields actually read from TaskInfo. There is deliberately no
     * deserializer: the token must stay a real broker-held Binder object. */
    public static final class Task {
        final int id,display,user,parent,uid,topUid,activities;
        final Object token;
        final String intentComponent,base,top,real,orig;
        final boolean running,visible;
        public Task(int id,int display,int user,int parent,int uid,int topUid,int activities,Object token,
                String intentComponent,String base,String top,String real,String orig,boolean running,boolean visible){
            this.id=id;this.display=display;this.user=user;this.parent=parent;this.uid=uid;this.topUid=topUid;this.activities=activities;
            this.token=token;this.intentComponent=intentComponent;this.base=base;this.top=top;this.real=real;this.orig=orig;
            this.running=running;this.visible=visible;
        }
    }

    public static final class Bound {
        private final Locator locator;
        private final Session scope;
        private final Task original;
        private final int ownedDisplay;
        private long observed;
        private boolean refused;
        private Bound(Locator locator,Session scope,int peerUid,int peerPid,
                Task actual,int ownedDisplay,long now){
            need(locator!=null&&scope!=null&&scope.targetUserId==10&&ownedDisplay>1
                    &&locator.uid==scope.appUid&&locator.uid==peerUid&&locator.pid==peerPid
                    &&locator.ownerSha256.equals(scope.ownerSha256),"CONTROLLER_UI_CALLER_BINDING");
            need(locator.captured<=scope.createdElapsedMs&&now>=scope.createdElapsedMs
                    &&now>=locator.captured&&now-locator.captured<=MAX_START_AGE_MS&&now<scope.expiresElapsedMs,
                    "CONTROLLER_UI_START_EXPIRED");
            this.locator=locator;this.scope=scope;this.ownedDisplay=ownedDisplay;
            requireActual(actual);original=actual;observed=now;
        }
        private void requireActual(Task actual){
            need(actual!=null&&actual.id==locator.task&&actual.display==locator.display&&actual.display!=ownedDisplay
                    &&actual.user==0&&actual.uid==locator.uid&&actual.topUid==locator.uid&&actual.token!=null
                    &&actual.running&&actual.visible&&actual.activities==1
                    &&COMPONENT.equals(actual.intentComponent)&&COMPONENT.equals(actual.base)
                    &&COMPONENT.equals(actual.top)&&COMPONENT.equals(actual.real)
                    &&(actual.orig==null||COMPONENT.equals(actual.orig)),"CONTROLLER_UI_ACTUAL_TASK_INVALID");
        }
        public synchronized void requirePeer(int uid,int pid){
            try{need(!refused&&uid==locator.uid&&pid==locator.pid,"CONTROLLER_UI_CALLER_CHANGED");}
            catch(RuntimeException invalid){refused=true;throw invalid;}
        }
        public synchronized void recheck(Task actual,long now){
            try{
                need(!refused&&now>=observed&&now<scope.expiresElapsedMs,"CONTROLLER_UI_LEASE_OR_CLOCK");
                requireActual(actual);
                need(actual.parent==original.parent&&Objects.equals(actual.token,original.token),"CONTROLLER_UI_TOKEN_OR_PARENT_CHANGED");
                observed=now;
            }catch(RuntimeException invalid){refused=true;throw invalid;}
        }
        int task(){return locator.task;}
        int display(){return locator.display;}
        int uid(){return locator.uid;}
        int rootTask(){return original.parent<0?original.id:original.parent;}
        int ownedDisplay(){return ownedDisplay;}
        synchronized void requireValid(){need(!refused,"CONTROLLER_UI_PREVIOUS_REFUSAL");}
        boolean taskRow(int display,int task,int user,String affinity,String intent){
            return !refused&&display==locator.display&&task==locator.task&&user==0
                    &&((locator.uid+":org.trillionnium.hepta.local").equals(affinity)||COMPONENT.equals(intent));
        }
        boolean activityRow(int display,int task,int user,String component){
            return !refused&&display==locator.display&&task==locator.task&&user==0&&COMPONENT.equals(component);
        }
        public synchronized Map<String,Object> evidence(){
            Map<String,Object> out=new LinkedHashMap<String,Object>();
            out.put("schema","hepta.permission-controller-ui-observation.v1");
            out.put("generation",scope.generation);out.put("scope_sha256",scope.sha256);
            out.put("locator_sha256",ProfileIdentity.sha(locator.wire()));out.put("owner_uid",locator.uid);out.put("owner_pid",locator.pid);
            out.put("task_id",locator.task);out.put("display_id",locator.display);out.put("owned_display_id",ownedDisplay);
            out.put("component",COMPONENT);out.put("actual_task_token_retained",true);out.put("observed_elapsed_ms",observed);
            out.put("observation_valid",!refused);
            out.put("serialized_locator_grants_authority",false);out.put("physical_input_authorized",false);
            return Collections.unmodifiableMap(out);
        }
    }
    public static Bound bind(Locator locator,Session scope,int peerUid,int peerPid,
            Task actual,int ownedDisplay,long now){
        return new Bound(locator,scope,peerUid,peerPid,actual,ownedDisplay,now);
    }
}
