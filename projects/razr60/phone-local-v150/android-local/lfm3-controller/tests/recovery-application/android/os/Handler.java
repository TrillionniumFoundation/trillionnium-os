package android.os;
public final class Handler {
    private static final java.util.Queue<Runnable> QUEUE=new java.util.concurrent.ConcurrentLinkedQueue<Runnable>();
    public static boolean acceptPosts=true;
    public Handler(Looper looper){if(looper!=Looper.getMainLooper())throw new IllegalArgumentException("main only");}
    public boolean post(Runnable work){if(!acceptPosts)return false;return QUEUE.offer(work);}
    public static void drain(){
        if(Looper.myLooper()!=Looper.getMainLooper())throw new IllegalStateException("main only");
        Runnable work;while((work=QUEUE.poll())!=null)work.run();
    }
    public static int pending(){return QUEUE.size();}
    public static void reset(){QUEUE.clear();acceptPosts=true;}
}
