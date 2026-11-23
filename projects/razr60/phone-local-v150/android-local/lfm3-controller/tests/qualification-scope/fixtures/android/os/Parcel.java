package android.os;
/** Type-only platform boundary. Never a real or permissive profile serializer. */
public final class Parcel {
 public static Parcel obtain(){throw new AssertionError("legacy host fixture has no profile parcel");}
 public int dataSize(){throw new AssertionError();}public int readInt(){throw new AssertionError();}
 public void setDataPosition(int position){throw new AssertionError();}public int dataPosition(){throw new AssertionError();}
 public byte[] marshall(){throw new AssertionError();}public void recycle(){throw new AssertionError();}
}
