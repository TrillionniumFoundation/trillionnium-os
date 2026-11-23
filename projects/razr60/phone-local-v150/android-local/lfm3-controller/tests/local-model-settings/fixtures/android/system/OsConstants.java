package android.system;
public final class OsConstants {private OsConstants(){}public static final int ENOENT=2,EPIPE=32,O_RDONLY=0,O_WRONLY=1,O_CREAT=64,O_EXCL=128,O_NOFOLLOW=131072,O_CLOEXEC=524288;public static boolean S_ISREG(int m){return(m&0170000)==0100000;}public static boolean S_ISDIR(int m){return(m&0170000)==0040000;}}
