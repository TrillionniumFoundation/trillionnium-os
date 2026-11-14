package org.trillionnium.hepta.local;

import java.util.Map;

/** Type-only legacy non-Web boundary. No quotation, completion proof or authority can be created. */
final class WebShoppingQuote {
    static final String SCHEMA="hepta.mi-visible-search-card-quote.v1";
    private WebShoppingQuote(){throw unavailable();}
    private static AssertionError unavailable(){return new AssertionError("legacy non-Web fixture has no shopping quote capability");}
    static final class Completion {
        private Completion(){throw unavailable();}
        boolean consume(TaskCompletionGate gate,WebTaskDomain domain,NotesCompletionEvidence.Frame frame,String run){throw unavailable();}
        Map<String,Object> summary(){throw unavailable();}
    }
}
