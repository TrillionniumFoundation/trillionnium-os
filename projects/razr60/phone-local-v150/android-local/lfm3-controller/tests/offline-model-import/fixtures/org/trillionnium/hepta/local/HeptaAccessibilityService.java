package org.trillionnium.hepta.local;
final class HeptaAccessibilityService {
    static HeptaAccessibilityService current;
    static HeptaAccessibilityService connected(){return current;}
    static String message(Throwable failure){return failure.getMessage()==null?failure.getClass().getSimpleName():failure.getMessage();}
}

