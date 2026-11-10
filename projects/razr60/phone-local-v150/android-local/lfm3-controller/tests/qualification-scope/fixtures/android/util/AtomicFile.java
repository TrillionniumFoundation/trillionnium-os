package android.util;
import java.io.*;
public final class AtomicFile {private final File file;public AtomicFile(File f){file=f;}public File getBaseFile(){return file;}public FileOutputStream startWrite()throws IOException{return new FileOutputStream(file);}public void finishWrite(FileOutputStream out)throws IOException{out.close();}public void failWrite(FileOutputStream out){try{out.close();}catch(IOException ignored){}}}
