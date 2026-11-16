package android.os;
import java.io.*;import java.nio.charset.StandardCharsets;
public final class Parcel {
 public static int obtained,recycled;private final ByteArrayOutputStream bytes=new ByteArrayOutputStream();private final DataOutputStream out=new DataOutputStream(bytes);private ByteArrayInputStream input;private DataInputStream in;private boolean closed;
 public static Parcel obtain(){obtained++;return new Parcel();}
 public void writeInt(int v){try{out.writeInt(v);}catch(IOException e){throw new IllegalStateException(e);}}
 public int readInt(){try{return in.readInt();}catch(IOException e){throw new IllegalStateException(e);}}
 public void writeString(String s){byte[] b=s.getBytes(StandardCharsets.UTF_8);writeInt(b.length);try{out.write(b);}catch(IOException e){throw new IllegalStateException(e);}}
 public String readString(){int n=readInt();if(n<0||n>100000)throw new IllegalStateException("string bound");byte[] b=new byte[n];try{in.readFully(b);}catch(IOException e){throw new IllegalStateException(e);}return new String(b,StandardCharsets.UTF_8);}
 public int dataSize(){return bytes.size();}public int dataPosition(){return bytes.size()-input.available();}
 public void setDataPosition(int p){if(p!=0)throw new IllegalArgumentException("test only starts at zero");input=new ByteArrayInputStream(bytes.toByteArray());in=new DataInputStream(input);}
 public byte[] marshall(){return bytes.toByteArray();}
 public void recycle(){if(closed)throw new AssertionError("double recycle");closed=true;recycled++;}
}