package org.trillionnium.hepta.local;

/** Complete native comparison rejected its old frame. Not a Permit or a benign-change classification. */
final class WebNativeObservationChanged extends IllegalArgumentException {
    private static final long serialVersionUID=1L;
    final String nativePath,diagnostic;
    WebNativeObservationChanged(String prefix,String path){this(prefix,path,null);}
    WebNativeObservationChanged(String prefix,String path,String diagnostic){
        super(prefix+path);nativePath=path;
        this.diagnostic=diagnostic!=null&&diagnostic.length()<=4096?diagnostic:null;
    }
}
