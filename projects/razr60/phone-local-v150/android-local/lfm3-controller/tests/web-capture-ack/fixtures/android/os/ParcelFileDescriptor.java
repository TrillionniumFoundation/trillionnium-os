package android.os;import java.io.*;import android.system.*;
/** Independent read-only host FD duplicate; no Android Binder or UID authentication claim. */
public final class ParcelFileDescriptor implements AutoCloseable {public static final int MODE_READ_ONLY=268435456;private final File file;private final FileDescriptor fd;
 private ParcelFileDescriptor(File f)throws Exception{file=f;fd=Os.open(f.getPath(),OsConstants.O_RDONLY|OsConstants.O_NOFOLLOW,0);}
 public static ParcelFileDescriptor open(File f,int mode)throws Exception{if(mode!=MODE_READ_ONLY)throw new IllegalArgumentException("readonly");return new ParcelFileDescriptor(f);}
 public long getStatSize()throws Exception{return Os.fstat(fd).st_size;}public FileDescriptor getFileDescriptor(){return fd;}public void close()throws Exception{Os.close(fd);}
 public void writeToParcel(Parcel p,int flags)throws Exception{p.fixtureObject(new ParcelFileDescriptor(file));}
 public interface Creator{ParcelFileDescriptor createFromParcel(Parcel p);}public static final Creator CREATOR=p->(ParcelFileDescriptor)p.fixtureObject();
}