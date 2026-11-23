package android.content.res;
public final class AssetManager {private final java.io.File dir;public AssetManager(java.io.File d){dir=d;}public java.io.InputStream open(String n)throws java.io.IOException{return new java.io.FileInputStream(new java.io.File(dir,n));}}
