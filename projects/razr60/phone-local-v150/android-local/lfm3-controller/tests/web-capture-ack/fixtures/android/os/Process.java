package android.os;
public final class Process {
 private static final InheritableThreadLocal<Integer> UID=new InheritableThreadLocal<Integer>(){protected Integer initialValue(){return 10481;}};
 public static int myUid(){return UID.get();} public static int myPid(){return 123;}
 public static void fixtureUid(int uid){UID.set(uid);}
}