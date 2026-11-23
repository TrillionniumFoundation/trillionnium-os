package org.trillionnium.hepta.local;

import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;

/** Keeps the shared no-child lease until completion handling finishes, on every exception path. */
public final class RecoveryDispatch {
    private RecoveryDispatch(){}
    public interface Lease extends AutoCloseable { void close(); }
    public interface LeaseFactory { Lease acquire() throws Exception; }
    public interface Work<T> { T run() throws Exception; }
    public interface Completion<T> { void finished(T value,Exception failure) throws Exception; }
    public static <T> void start(LeaseFactory factory,Executor worker,Executor completion,
            Work<T> work,Completion<T> callback)throws Exception{
        final Lease lease=factory.acquire();
        if(lease==null)throw new IllegalStateException("no recovery lease");
        final AtomicBoolean started=new AtomicBoolean(),delivered=new AtomicBoolean(),released=new AtomicBoolean();
        final Runnable release=new Runnable(){public void run(){if(released.compareAndSet(false,true))lease.close();}};
        try{
            worker.execute(new Runnable(){public void run(){
                if(!started.compareAndSet(false,true))return;
                T value=null;Exception failure=null;
                try{value=work.run();}catch(Exception e){failure=e;}
                catch(Throwable e){release.run();throw e;}
                final T result=value;final Exception problem=failure;
                try{
                    completion.execute(new Runnable(){public void run(){
                        if(!delivered.compareAndSet(false,true))return;
                        try{callback.finished(result,problem);}
                        catch(Exception ignored){/* The caller's blocked state is retained; lease still closes. */}
                        finally{release.run();}
                    }});
                }catch(RuntimeException e){release.run();throw e;}
            }});
        }catch(RuntimeException e){release.run();throw e;}
    }
}
