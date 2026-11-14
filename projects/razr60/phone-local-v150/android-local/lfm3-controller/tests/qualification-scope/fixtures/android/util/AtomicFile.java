package android.util;
import java.io.*;
public final class AtomicFile {private final File file;public AtomicFile(File f){file=f;}public File getBaseFile(){return file;}public FileOutputStream startWrite()throws IOException{FileOutputStream out=new FileOutputStream(file);android.system.Os.trackOutput(out.getFD(),file.getPath());return out;}public void finishWrite(FileOutputStream out)throws IOException{android.system.Os.forgetOutput(out.getFD());out.close();}public void failWrite(FileOutputStream out){try{android.system.Os.forgetOutput(out.getFD());out.close();}catch(IOException ignored){}}}
