package android.util;
/** Fixed diagnostic logging boundary only; no Android log transport in host tests. */
public final class Log {private Log(){}public static int i(String tag,String text){return 0;}public static int e(String tag,String text){return 0;}}
