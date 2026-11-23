package android.system;
public final class ErrnoException extends Exception {private static final long serialVersionUID=1L;public final int errno;public ErrnoException(String call,int n){super(call+" errno="+n);errno=n;}public ErrnoException(String call,int n,Throwable cause){super(call+" errno="+n,cause);errno=n;}}
