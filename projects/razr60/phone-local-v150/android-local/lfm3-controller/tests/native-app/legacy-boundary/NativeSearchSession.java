package org.trillionnium.hepta.local;

/** Pure signature boundary only. Every constructor and authority operation throws.
 * Actual search Session gates must compile the production class instead. */
final class NativeSearchSession {
    private NativeSearchSession(){throw unavailable();}
    static final class Offer {
        final NativeSearchPlanning planning=null;
        private Offer(){throw unavailable();}
        void requireForGrammar(TaskAuthorization.Frame frame){throw unavailable();}
    }
    private static UnsupportedOperationException unavailable(){
        return new UnsupportedOperationException("Native search Session is not executed by legacy pure host suites");
    }
}
