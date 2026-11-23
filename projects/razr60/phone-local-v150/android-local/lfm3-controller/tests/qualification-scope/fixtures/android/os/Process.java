package android.os;
public final class Process {private Process(){}public static int myUid(){try{return ((Number)java.nio.file.Files.getAttribute(java.nio.file.Paths.get("."),"unix:uid")).intValue();}catch(Exception e){throw new IllegalStateException(e);}}public static int myPid(){return 123;}}
