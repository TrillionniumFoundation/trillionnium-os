package android.os;
public final class SystemClock {private SystemClock(){}public static long elapsedRealtime(){return System.nanoTime()/1000000L;}public static void sleep(long millis){try{Thread.sleep(millis);}catch(InterruptedException interrupted){Thread.currentThread().interrupt();}}}
