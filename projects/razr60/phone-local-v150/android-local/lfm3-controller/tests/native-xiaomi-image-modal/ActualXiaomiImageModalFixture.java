package org.trillionnium.hepta.local;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Exact detached DTO projection of the saved observed frame. The saved JSON
 * defaults are decoded according to PhoneObservation.Node.json(); child text
 * is observed empty. This replay supplies no live lease, installed App proof,
 * dispatch, model result or current-device qualification. */
final class ActualXiaomiImageModalFixture {
    static final String OWNER="在小米商城查一下小米AX3000T的售价";
    static final String ORIGINAL_SHA="b4f885d60fd2d461cb4cc72dd895cc78ac8c11b62ca7ccece8e213f7aed55038";
    static NativeAppEvidence.Frame frame(){
        List<NativeAppEvidence.Node> nodes=new ArrayList<NativeAppEvidence.Node>();
        nodes.add(new NativeAppEvidence.Node("n0","com.xiaomi.shop","android.widget.ImageView","","","","0/0","android.widget.FrameLayout","946adfc4bf863ceb41dfa3acff45132939d7eda01220ecb49043b1f074891451","",
                216,333,504,815,true,false,true,false,false,Boolean.FALSE,Boolean.FALSE,Boolean.FALSE,Collections.<String>emptySet()));
        nodes.add(new NativeAppEvidence.Node("n1","com.xiaomi.shop","android.widget.ImageView","","","","0/1","android.widget.FrameLayout","873440fd5abd6f7e4b452559f88ba2cc61e59e7d7912abdc1cad5e505b776131","",
                309,845,411,947,true,false,true,false,false,Boolean.FALSE,Boolean.FALSE,Boolean.FALSE,Collections.<String>emptySet()));
        return new NativeAppEvidence.Frame("6acbbe0c9a4a4b1ca12a91ab6c596768","8d76e0c231b30a3c18fd4c57967ba8546e6d8d9fe0a6132086c24536a540b421","1dd8f49a5b90995ff035ec20980cbc9c0eceec6511603620785d9282280989a7","e698a3aa764f67b15d252545fce642bf974c2a1c08f6bc295cee0345d1229cad","5423afc74e10604c644d2d1177e836e60c34f9fd78f747ff7a2d7374c3a9ba22","c5ab371e41a6455884ce6e04addd7e97","com.xiaomi.shop","535cae0a-acea-488f-a363-710f552ffd9c","2bc26d1d3d91b3b8be8cbe8d76a79988f9c1a9462edf49390cc98d49ad5a2ece","72afba8fd824420e4007f8e5359fcf65221e211f151e148a79107df0f999169d","f1f38d0e4c18bea45e0b0280d747376edc983c7a3553bd31ca1eed5b299699d5","b4f885d60fd2d461cb4cc72dd895cc78ac8c11b62ca7ccece8e213f7aed55038","96d8016773660b7fd3e6ede3c3db7f2334bf12fa201adf459d5044afc130d31a",
                4,38,0,720,1280,216,333,504,947,
                2660574L,false,true,nodes,1,true);
    }
    private ActualXiaomiImageModalFixture(){}
}
