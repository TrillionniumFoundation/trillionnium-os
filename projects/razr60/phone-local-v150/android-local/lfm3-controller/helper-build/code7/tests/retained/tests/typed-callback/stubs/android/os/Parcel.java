package android.os;
/** Observable transport double; deliberately contains no evidence policy. */
public final class Parcel {
    public static int obtained,recycled;
    public String token,text;
    public int marker=-1,fdWrites;
    private boolean done;
    public static Parcel obtain(){obtained++;return new Parcel();}
    public static void reset(){obtained=0;recycled=0;}
    public void writeInterfaceToken(String value){token=value;}
    public void writeString(String value){text=value;}
    public void writeInt(int value){marker=value;}
    public void recycle(){if(done)throw new AssertionError("double parcel recycle");done=true;recycled++;}
}
