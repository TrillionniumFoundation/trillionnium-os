package org.trillionnium.hepta.background;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.json.JSONObject;

/** Executes the exact production create-return tail, cleanup binder and cleanup
 * worker. Display, package lookup and TaskInfo are explicit inert host ports. */
public final class NotesCreateFailureBrokerHostTest {
    static int cases,checks;
    interface Work { void run()throws Exception; }
    static void yes(boolean value){checks++;if(!value)throw new AssertionError("early-create cleanup boundary");}
    static void refuse(Work work)throws Exception{
        try{work.run();}catch(Exception expected){checks++;return;}
        throw new AssertionError("early-create failure was accepted");
    }
    static void test(String name,Work work)throws Exception{
        PublicPersonalNotesReader.constructorFailure=false;PublicPersonalNotesReader.constructorUid=0;
        PublicPersonalNotesReader.constructorEntered=null;PublicPersonalNotesReader.constructorProceed=null;
        work.run();cases++;System.out.println("PASS "+name);
    }
    static NotesCleanupAdapterFixture fresh()throws Exception{
        NotesCleanupAdapterFixture f=new NotesCleanupAdapterFixture();
        f.publicNotesCustody=PersonalNotesCustodyHostTest.fresh();f.publicNotesCustody.beforeCreate();
        f.publicNotesReader=null;f.displayId=-1;f.state="INITIAL";return f;
    }
    static void cleanup(NotesCleanupAdapterFixture f)throws Exception{
        f.publicNotesCustody.retireAdmission();f.cleanupStarted.set(true);f.start();f.finished();
    }
    public static JSONObject emptyProof(PublicOwnGroupPolicy.Scope scope)throws Exception{
        PublicPersonalNotesCustody c=new PublicPersonalNotesCustody(scope.generation,scope.sha256,
                PersonalNotesCustodyHostTest.UID,PersonalNotesCustodyHostTest.global(-1),
                PersonalNotesCustodyHostTest.recents(PersonalNotesCustodyHostTest.raw()));
        c.beforeCreate();c.bindDisplay(7);c.retireAdmission();
        PublicPersonalNotesCustody.Frame frame=new PublicPersonalNotesCustody.Frame(
                PersonalNotesCustodyHostTest.global(-1),Collections.emptyList(),100,100);
        c.prepareRelease(frame,PersonalNotesCustodyHostTest.recents(PersonalNotesCustodyHostTest.raw()),100);
        c.enterRelease();c.releaseReturned();
        PersonalNotesCustodyHostTest.absence(c,PersonalNotesCustodyHostTest.raw(),200);
        PersonalNotesCustodyHostTest.absence(c,PersonalNotesCustodyHostTest.raw(),250);
        if(!c.known())throw new AssertionError("real custody empty proof did not close");
        return new JSONObject(c.evidence());
    }
    public static void main(String[] args)throws Exception{
        test("actual create tail orders cleanup identity before policy failure with inert empty census",()->{
            NotesCleanupAdapterFixture f=fresh();f.failPolicy=true;
            NotesCleanupAdapterFixture.VirtualDisplay handle=f.virtual;
            refuse(()->f.createTail(handle));
            yes(f.publicNotesReader!=null&&f.displayId==7&&f.imeCalls==1&&f.policyCalls==1&&f.powerCalls==0);
            yes(!f.createInFlight&&!f.effectInFlight&&f.launched.isEmpty());
            cleanup(f);yes(handle.calls==1&&f.publicNotesCustody.known()&&"RELEASED".equals(f.state));
            JSONObject proof=new JSONObject(f.publicNotesCustody.evidence());
            yes(!proof.getBoolean("launch_dispatched")&&proof.getJSONArray("actual_observed_tasks").length()==0);
            yes(proof.getInt("absence_reads")==2&&proof.getBoolean("create_attempted")&&!proof.getBoolean("no_display_create_attempted"));
        });
        test("IME failure also retains exact create handle cleanup",()->{
            NotesCleanupAdapterFixture f=fresh();f.failIme=true;NotesCleanupAdapterFixture.VirtualDisplay handle=f.virtual;
            refuse(()->f.createTail(handle));cleanup(f);
            yes(handle.calls==1&&f.publicNotesCustody.known()&&f.policyCalls==0&&f.powerCalls==0);
        });
        test("early binding does not waive unresolved hidden history changes",()->{
            NotesCleanupAdapterFixture f=fresh();f.failPolicy=true;NotesCleanupAdapterFixture.VirtualDisplay handle=f.virtual;
            refuse(()->f.createTail(handle));
            f.publicNotesReader.raw=PersonalNotesCustodyHostTest.hidden(PersonalNotesCustodyHostTest.raw(),"Task{ff #799 type=standard}");
            cleanup(f);yes(handle.calls==0&&!f.publicNotesCustody.known()&&f.publicNotesCustody.retain());
        });
        test("read-only reader constructor failure retains UNKNOWN without release",()->{
            NotesCleanupAdapterFixture f=fresh();PublicPersonalNotesReader.constructorFailure=true;
            NotesCleanupAdapterFixture.VirtualDisplay handle=f.virtual;refuse(()->f.createTail(handle));cleanup(f);
            yes(f.publicNotesReader==null&&handle.calls==0&&!f.publicNotesCustody.known()&&f.publicNotesCustody.retain());
        });
        test("changed installed Notes UID never publishes a cleanup reader",()->{
            NotesCleanupAdapterFixture f=fresh();PublicPersonalNotesReader.constructorUid=PersonalNotesCustodyHostTest.UID+1;
            NotesCleanupAdapterFixture.VirtualDisplay handle=f.virtual;refuse(()->f.createTail(handle));cleanup(f);
            yes(f.publicNotesReader==null&&handle.calls==0&&!f.publicNotesCustody.known());
        });
        test("unknown create-return handle cannot become not-created cleanup",()->{
            NotesCleanupAdapterFixture f=fresh();refuse(()->f.createTail(null));cleanup(f);
            yes(f.publicNotesCustody.createAttempted()&&!f.publicNotesCustody.known()&&f.publicNotesCustody.retain());
        });
        for(final int physical:new int[]{0,1})test("physical display "+physical+" never acquires cleanup release authority",()->{
            NotesCleanupAdapterFixture f=fresh();f.returnedId=physical;NotesCleanupAdapterFixture.VirtualDisplay handle=f.virtual;
            refuse(()->f.createTail(handle));cleanup(f);yes(handle.calls==0&&f.publicNotesReader==null&&!f.publicNotesCustody.known());
        });
        test("replaced create-return handle cannot be bound",()->{
            NotesCleanupAdapterFixture f=fresh();f.displayId=7;f.createInFlight=true;
            f.publicCreateReturnedHandle=f.new VirtualDisplay();
            refuse(()->f.bindCreated(f.virtual));f.createInFlight=false;cleanup(f);
            yes(f.virtual.calls==0&&f.publicCreateReturnedHandle.calls==0&&!f.publicNotesCustody.known());
        });
        for(final String attempted:new String[]{"launch","effect","tool"})test("prior "+attempted+" blocks initial cleanup binding",()->{
            NotesCleanupAdapterFixture f=fresh();
            if("launch".equals(attempted))f.launched.add(PublicPersonalNotesCustody.PACKAGE);
            if("effect".equals(attempted))f.effectInFlight=true;
            if("tool".equals(attempted))f.fixedToolsConsumed.add("notes.create");
            NotesCleanupAdapterFixture.VirtualDisplay handle=f.virtual;refuse(()->f.createTail(handle));cleanup(f);
            yes(handle.calls==0&&f.publicNotesReader==null&&!f.publicNotesCustody.known());
        });
        test("closing while constructor is in flight publishes only cleanup identity before unlock",()->{
            NotesCleanupAdapterFixture f=fresh();NotesCleanupAdapterFixture.VirtualDisplay handle=f.virtual;
            CountDownLatch entered=new CountDownLatch(1),proceed=new CountDownLatch(1);
            PublicPersonalNotesReader.constructorEntered=entered;PublicPersonalNotesReader.constructorProceed=proceed;
            AtomicReference<Throwable> failure=new AtomicReference<Throwable>();
            Thread create=new Thread(()->{try{f.createTail(handle);}catch(Throwable error){failure.set(error);}});
            create.start();yes(entered.await(1,TimeUnit.SECONDS));
            f.closing.set(true);f.publicNotesCustody.retireAdmission();f.cleanupStarted.set(true);f.start();
            yes(handle.calls==0&&f.publicNotesReader==null);proceed.countDown();create.join(1500);f.finished();
            yes(!create.isAlive()&&failure.get()!=null&&"SESSION_CLOSING".equals(failure.get().getMessage()));
            yes(handle.calls==1&&f.publicNotesCustody.known()&&f.imeCalls==0&&f.policyCalls==0&&f.powerCalls==0);
        });
        test("successful create still requires the original IME policy power and final guard",()->{
            NotesCleanupAdapterFixture f=fresh();f.createTail(f.virtual);
            yes("ACTIVE".equals(f.state)&&f.imeCalls==1&&f.policyCalls==1&&f.powerCalls==1&&f.guardCalls==1);
            yes(f.virtual.calls==0&&f.publicNotesReader!=null&&!f.publicNotesCustody.known());
        });
        System.out.println("{\"cases\":"+cases+",\"assertions\":"+checks+",\"passed\":true,\"phone_contacted\":false}");
    }
}
