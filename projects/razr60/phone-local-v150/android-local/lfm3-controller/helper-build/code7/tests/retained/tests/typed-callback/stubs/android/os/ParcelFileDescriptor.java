package android.os;
/** No real file descriptor is opened by this host fixture. */
public final class ParcelFileDescriptor {
    public static int opened,closed;
    private boolean done;
    public ParcelFileDescriptor(){opened++;}
    public static void reset(){opened=0;closed=0;}
    public void writeToParcel(Parcel p,int flags){if(done)throw new AssertionError("closed FD serialized");p.fdWrites++;}
    public void close(){if(done)throw new AssertionError("double FD close");done=true;closed++;}
}
