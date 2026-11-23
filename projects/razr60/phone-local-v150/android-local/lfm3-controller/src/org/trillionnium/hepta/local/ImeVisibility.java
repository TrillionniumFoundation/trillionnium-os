package org.trillionnium.hepta.local;

/** Only input-method window visibility; no key, text, app or node inspection. */
public enum ImeVisibility {
    VISIBLE("true"), HIDDEN("false"), UNKNOWN("unknown");

    public final String fingerprintValue;
    ImeVisibility(String value){fingerprintValue=value;}
    public Boolean value(){return this==UNKNOWN?null:Boolean.valueOf(this==VISIBLE);}

    /** Absence proves hidden only in a complete window list containing the target. */
    public static ImeVisibility observed(boolean complete,boolean targetWindowPresent,boolean visibleImePresent){
        if(!complete||!targetWindowPresent)return UNKNOWN;
        return visibleImePresent?VISIBLE:HIDDEN;
    }
}
