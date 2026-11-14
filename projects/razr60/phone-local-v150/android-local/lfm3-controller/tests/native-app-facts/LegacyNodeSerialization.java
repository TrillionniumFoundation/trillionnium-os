package org.trillionnium.hepta.local;
import android.graphics.Rect;
/** Runs against original and new actual Node extraction; exact JSON must remain equal. */
public final class LegacyNodeSerialization {
    private LegacyNodeSerialization() {}
    public static void main(String[] args){
        PhoneObservation.Node n=new PhoneObservation.Node("n0","ctrip.android.view","android.widget.TextView","test:id/choice","单程","",
                new Rect(0,0,20,20),false,false,false,true,false,false,ObservedChildText.notApplicable(),
                ObservedScrollActions.UNKNOWN,ObservedImeEnter.UNKNOWN,null,false,null,"0/0","android.widget.LinearLayout");
        System.out.println(n.json().toString());
    }
}
