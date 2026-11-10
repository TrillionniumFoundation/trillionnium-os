package android.os;
public final class Looper {
    private static final Looper MAIN=new Looper();
    private static Thread owner=Thread.currentThread();
    private Looper(){}
    public static Looper getMainLooper(){return MAIN;}
    public static Looper myLooper(){return Thread.currentThread()==owner?MAIN:null;}
    public static void resetMain(){owner=Thread.currentThread();}
}
