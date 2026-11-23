package android.os;
public final class Handler {
 private static final Thread TEST_MAIN=Thread.currentThread();
 public static volatile boolean hold,holdPosts;public static final java.util.List<Runnable> queued=java.util.Collections.synchronizedList(new java.util.ArrayList<Runnable>());
 public Handler(Looper l){}public boolean post(Runnable r){if(holdPosts||(hold&&Thread.currentThread()!=TEST_MAIN))queued.add(r);else r.run();return true;}
 public boolean postDelayed(Runnable r,long delay){if(hold)queued.add(r);else r.run();return true;}
 public void removeCallbacks(Runnable r){queued.remove(r);}
 public static void drain(){hold=false;holdPosts=false;for(;;){Runnable next;synchronized(queued){if(queued.isEmpty())return;next=queued.remove(0);}next.run();}}
}
