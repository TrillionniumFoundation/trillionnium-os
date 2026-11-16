package org.trillionnium.hepta.local;

/** Complete native comparison rejected its old frame. Not a Permit or a benign-change classification. */
final class WebNativeObservationChanged extends IllegalArgumentException {
    private static final long serialVersionUID=1L;
    final String nativePath;
    WebNativeObservationChanged(String prefix,String path){super(prefix+path);nativePath=path;}
}
