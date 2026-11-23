package org.trillionnium.hepta.background;

import org.trillionnium.hepta.local.ProfilePermissionInitialization;
import org.trillionnium.hepta.local.ProfilePermissionInitialization.*;
import java.util.*;

/** Synthetic coordinator fixture shared with the original unchanged ownership
 * tests. No Android Binder, accessibility node or physical screen is emulated. */
public final class UiPermissionFixture {
    private final ProfilePermissionTransientHostTest.Adapter adapter;
    private final ProfileOwnedTask task;
    private final Object title=new Object(),deny=new Object(),fine=new Object(),coarse=new Object();
    private final Map<Integer,String> physical=new LinkedHashMap<Integer,String>();
    public UiPermissionFixture(String dump)throws Exception{
        ProfilePermissionTransientHostTest.fixtureShape(dump);
        adapter=new ProfilePermissionTransientHostTest.Adapter(dump);task=adapter.start(false);adapter.permission=true;
        char[] a=new char[64],b=new char[64];Arrays.fill(a,'a');Arrays.fill(b,'b');physical.put(0,new String(a));physical.put(1,new String(b));
    }
    private Node node(Object handle,String id,String label,boolean button,boolean radio,boolean checked){
        return new Node(handle,ProfilePermissionTransient.PACKAGE,14,id,button?"Button":radio?"RadioButton":"TextView",
                label,"","bounds",true,true,button,button,radio,checked);
    }
    public Snapshot snapshot(boolean location,long now)throws Exception{
        adapter.f.now=now;ProfileOwnedTask.PermissionRead live=task.permissionForInitialization(14,300,now+1800);
        PermissionWindowObservation sent=PermissionWindowObservation.fromLive(live,physical,now);
        PermissionWindowObservation received=PermissionWindowObservation.fromWire(sent.wire(),live.target);
        List<Node> nodes=new ArrayList<Node>();
        nodes.add(node(title,ProfilePermissionInitialization.MESSAGE,location?"允许携程访问设备位置吗？":"允许此项未知权限吗？",false,false,false));
        nodes.add(node(deny,ProfilePermissionInitialization.DENY,"不允许",true,false,false));
        if(location){nodes.add(node(fine,ProfilePermissionInitialization.FINE,"精确位置",false,true,true));
            nodes.add(node(coarse,ProfilePermissionInitialization.COARSE,"大致位置",false,true,false));}
        List<Window> windows=Arrays.asList(new Window(14,7,300,1,8,ProfilePermissionTransient.PACKAGE,false,true),
                new Window(13,7,300,1,1,ProfileTarget.CTRIP,false,false));
        return new Snapshot(received,now,now,true,nodes,windows,physical);
    }
}
