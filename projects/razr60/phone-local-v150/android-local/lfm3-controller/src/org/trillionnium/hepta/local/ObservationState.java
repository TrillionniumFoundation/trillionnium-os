package org.trillionnium.hepta.local;

/** Immutable app-tree identity plus separately observed input-method visibility. */
public final class ObservationState {
    public final String appTreeSha256;
    public final ImeVisibility imeVisibility;

    public ObservationState(String appTreeSha256,ImeVisibility imeVisibility){
        if(appTreeSha256==null||appTreeSha256.isEmpty()||imeVisibility==null)
            throw new IllegalArgumentException("complete observation state required");
        this.appTreeSha256=appTreeSha256;this.imeVisibility=imeVisibility;
    }

    /** For exact freshness checks, unknown is a distinct observed state. */
    public String fingerprintInput(){return appTreeSha256+"\nime_visible="+imeVisibility.fingerprintValue;}

    /** Null means IME progress is unknown, not that a keyboard appeared/disappeared. */
    public Boolean changedFrom(ObservationState before){
        if(before==null)throw new IllegalArgumentException("previous observation required");
        if(!appTreeSha256.equals(before.appTreeSha256))return Boolean.TRUE;
        if(imeVisibility==ImeVisibility.UNKNOWN||before.imeVisibility==ImeVisibility.UNKNOWN)return null;
        return Boolean.valueOf(imeVisibility!=before.imeVisibility);
    }
}
