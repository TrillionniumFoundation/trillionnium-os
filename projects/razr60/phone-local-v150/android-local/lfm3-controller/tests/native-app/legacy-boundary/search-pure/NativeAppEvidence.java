package org.trillionnium.hepta.local;
/** Only signatures newly referenced by the unreachable typed grammar/parser.
 * Every operation refuses; no existing evidence class is replaced. */
final class NativeAppEvidence {
    private NativeAppEvidence(){throw unavailable();}
    static boolean id(String value){throw unavailable();}
    static boolean sha(String value){throw unavailable();}
    private static UnsupportedOperationException unavailable(){
        return new UnsupportedOperationException("No native evidence in this old pure client fixture");
    }
}
