package org.trillionnium.hepta.local;

import android.net.LocalSocket;
import android.os.SystemClock;

/** Exact new service methods are extracted unchanged into ServicePolicyFixture.
 * Real BackgroundSession policy/transport logic runs against explicit fake IO. */
public final class ServiceScopeHostTest {
    interface Work{void run()throws Exception;}
    static int cases,assertions;
    static void yes(boolean v){assertions++;if(!v)throw new AssertionError("service scope invariant failed");}
    static void no(Work w)throws Exception{try{w.run();}catch(Exception expected){assertions++;return;}throw new AssertionError("service admitted retired scope");}
    static void test(String name,Work w)throws Exception{LocalSocket.reset();SystemClock.now=1000000;android.provider.Settings.Global.boot=10;android.os.Looper.worker=true;w.run();cases++;System.out.println("PASS "+name);}
    static ServicePolicyFixture bound(PublicOwnGroupSessionHostTest.Env env){ServicePolicyFixture service=new ServicePolicyFixture();service.bind(env.session);return service;}
    public static void main(String[] args)throws Exception{
        test("main locked check only admits the same object for worker scheduling",()->{try(PublicOwnGroupSessionHostTest.Env e=new PublicOwnGroupSessionHostTest.Env(false)){
            e.active();ServicePolicyFixture s=bound(e);SystemClock.now+=2000;android.os.Looper.worker=false;int calls=LocalSocket.connections;
            yes(!s.backgroundLocked(e.session)&&LocalSocket.connections==calls);
            android.os.Looper.worker=true;yes(!s.backgroundLocked(e.session)&&LocalSocket.connections==calls+1);e.physicalUnchanged();
        }});
        test("other session with same instruction is not the bound scope",()->{try(PublicOwnGroupSessionHostTest.Env a=new PublicOwnGroupSessionHostTest.Env(false);PublicOwnGroupSessionHostTest.Env b=new PublicOwnGroupSessionHostTest.Env(false)){
            ServicePolicyFixture s=bound(a);int calls=LocalSocket.connections;yes(s.backgroundLocked(b.session));yes(LocalSocket.connections==calls);
        }});
        test("foreground lock behavior stays separate",()->{ServicePolicyFixture s=new ServicePolicyFixture();s.foregroundLocked=true;yes(s.backgroundLocked(null));s.foregroundLocked=false;yes(!s.backgroundLocked(null));});
        test("worker refuses unknown live policy",()->{try(PublicOwnGroupSessionHostTest.Env e=new PublicOwnGroupSessionHostTest.Env(false)){
            e.active();ServicePolicyFixture s=bound(e);SystemClock.now+=600;LocalSocket.missing=true;yes(s.backgroundLocked(e.session));LocalSocket.missing=false;yes(s.backgroundLocked(e.session));
        }});
        test("last input gate performs actual fresh RPC before effect entry",()->{try(PublicOwnGroupSessionHostTest.Env e=new PublicOwnGroupSessionHostTest.Env(false)){
            e.active();ServicePolicyFixture s=bound(e);ServicePolicyFixture.ActionWork w=s.work(e.session,()->false);int calls=LocalSocket.connections;
            s.effect(w);yes(LocalSocket.connections==calls+1&&w.effects==1&&s.profileChecks==1);e.physicalUnchanged();
        }});
        test("RPC failure cannot enter effect or renew previous token",()->{try(PublicOwnGroupSessionHostTest.Env e=new PublicOwnGroupSessionHostTest.Env(false)){
            e.active();ServicePolicyFixture s=bound(e);ServicePolicyFixture.ActionWork w=s.work(e.session,()->false);LocalSocket.missing=true;
            no(()->s.effect(w));yes(w.effects==0);LocalSocket.missing=false;no(()->s.effect(w));yes(w.effects==0);
        }});
        test("cancellation during final RPC blocks effect",()->{try(PublicOwnGroupSessionHostTest.Env e=new PublicOwnGroupSessionHostTest.Env(false)){
            e.active();ServicePolicyFixture s=bound(e);final boolean[] stopped={false};ServicePolicyFixture.ActionWork w=s.work(e.session,()->stopped[0]);
            LocalSocket.responder=bytes->{byte[] answer=e.reply(bytes);stopped[0]=true;return answer;};no(()->s.effect(w));yes(w.effects==0);
        }});
        test("model admission uses actual owner controller auth and background object",()->{try(PublicOwnGroupSessionHostTest.Env e=new PublicOwnGroupSessionHostTest.Env(false)){
            e.active();ServicePolicyFixture s=bound(e);int calls=LocalSocket.connections;
            s.model(s.controller,e.session,s.authorization,()->false);yes(LocalSocket.connections==calls+1);
            no(()->s.model(new LocalTaskController(),e.session,s.authorization,()->false));yes(LocalSocket.connections==calls+1);
            TaskAuthorization.Gate copied=TaskAuthorization.parse(PublicOwnGroupSessionHostTest.OWNER).bind(PublicOwnGroupSessionHostTest.TASK);
            no(()->s.model(s.controller,e.session,copied,()->false));yes(LocalSocket.connections==calls+1);
        }});
        test("controller retired during model policy RPC cannot admit generate",()->{try(PublicOwnGroupSessionHostTest.Env e=new PublicOwnGroupSessionHostTest.Env(false)){
            e.active();ServicePolicyFixture s=bound(e);LocalTaskController captured=s.controller;
            LocalSocket.responder=bytes->{byte[] answer=e.reply(bytes);s.ownedController=new LocalTaskController();return answer;};
            no(()->s.model(captured,e.session,s.authorization,()->false));yes(s.modelAdmissions==0);
        }});
        test("background object replaced during model read cannot admit generate",()->{try(PublicOwnGroupSessionHostTest.Env e=new PublicOwnGroupSessionHostTest.Env(false)){
            e.active();ServicePolicyFixture s=bound(e);LocalSocket.responder=bytes->{byte[] answer=e.reply(bytes);s.taskBackground=null;return answer;};
            no(()->s.model(s.controller,e.session,s.authorization,()->false));yes(s.modelAdmissions==0);
        }});
        test("model result after display policy retirement is not admitted",()->{try(PublicOwnGroupSessionHostTest.Env e=new PublicOwnGroupSessionHostTest.Env(false)){
            e.active();ServicePolicyFixture s=bound(e);s.model(s.controller,e.session,s.authorization,()->false);yes(s.modelAdmissions==1);
            e.unique="virtual:replacement";no(()->s.model(s.controller,e.session,s.authorization,()->false));yes(s.modelAdmissions==1);
        }});
        System.out.println("{\"cases\":"+cases+",\"assertions\":"+assertions+",\"passed\":true,\"service_methods_exact\":true,\"phone_contacted\":false}");
    }
}
