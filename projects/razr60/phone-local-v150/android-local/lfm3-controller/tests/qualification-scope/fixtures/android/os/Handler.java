package android.os;
public final class Handler {
 public static boolean hold,holdPosts;public static final java.util.List<Runnable> queued=new java.util.ArrayList<Runnable>();
 public Handler(Looper l){}public boolean post(Runnable r){if(holdPosts)queued.add(r);else r.run();return true;}
 public boolean postDelayed(Runnable r,long delay){if(hold)queued.add(r);else r.run();return true;}
 public void removeCallbacks(Runnable r){queued.remove(r);}
 public static void drain(){hold=false;holdPosts=false;while(!queued.isEmpty())queued.remove(0).run();}
}
