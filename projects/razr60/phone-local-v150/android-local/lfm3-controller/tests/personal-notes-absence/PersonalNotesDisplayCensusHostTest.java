package org.trillionnium.hepta.background;

import android.hardware.display.DisplayManager;
import android.hardware.display.IDisplayManager;
import android.os.IBinder;
import android.os.ServiceManager;
import android.view.DisplayInfo;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.json.JSONArray;
import org.json.JSONObject;

/** Exact production reader, synthetic Binder rows; no Android runtime or phone operations. */
public final class PersonalNotesDisplayCensusHostTest {
    private static int assertions;
    private static final List<String> passed=new ArrayList<String>(),failed=new ArrayList<String>();
    interface Work {void run()throws Exception;}
    private static void yes(boolean value,String message){assertions++;if(!value)throw new AssertionError(message);}
    private static void test(String name,Work work){try{work.run();passed.add(name);}catch(Throwable failure){failed.add(name+": "+failure);}}
    private static void refuse(String code,Work work)throws Exception{
        try{work.run();throw new AssertionError("incomplete census accepted");}
        catch(Exception expected){yes(code.equals(expected.getMessage()),"wrong refusal: "+expected);}
    }
    public static final class Service implements IDisplayManager,IBinder {
        final Map<Integer,DisplayInfo> rows=new TreeMap<Integer,DisplayInfo>();
        final List<Boolean> calls=new ArrayList<Boolean>();
        int[] initial,ending;boolean nullIds;
        public int[] getDisplayIds(boolean includeDisabled){
            calls.add(includeDisabled);
            if(nullIds)return null;
            if(calls.size()>1&&ending!=null)return ending.clone();
            if(initial!=null)return initial.clone();
            List<Integer> ids=new ArrayList<Integer>();
            for(Map.Entry<Integer,DisplayInfo> e:rows.entrySet())if(includeDisabled||e.getValue().enabled)ids.add(e.getKey());
            int[] values=new int[ids.size()];for(int i=0;i<values.length;i++)values[i]=ids.get(i);return values;
        }
        public DisplayInfo getDisplayInfo(int id){return rows.get(id);}
    }
    private static final class Fixture {
        final PublicPersonalNotesAbsenceRecovery.Request request=new PersonalNotesAbsenceHostTest.Fixture().request();
        final Service service=new Service();final DisplayManager manager=new DisplayManager(service);
        Fixture()throws Exception{add(0,"physical-main",true);add(1,"physical-cover",true);}
        DisplayInfo add(int id,String name,boolean enabled){DisplayInfo row=new DisplayInfo(id,name);row.enabled=enabled;service.rows.put(id,row);return row;}
        JSONObject read()throws Exception{ServiceManager.service=service;return PersonalNotesDisplayCensusFixture.read(manager,request);}
    }
    private static boolean has(JSONObject result,int id){JSONArray rows=result.getJSONArray("rows");
        for(int i=0;i<rows.length();i++)if(rows.getJSONObject(i).getInt("id")==id)return true;return false;}
    public static void main(String[] args)throws Exception{
        test("complete stable census uses includeDisabled twice",()->{Fixture f=new Fixture();f.add(90,"foreign",true);JSONObject r=f.read();
            yes(r.getBoolean("complete")&&has(r,0)&&has(r,1)&&has(r,90),"full census missing");
            yes(f.service.calls.size()==2&&!f.service.calls.contains(Boolean.FALSE),"enabled-only or single enumeration");});
        test("disabled physical cover remains in census",()->{Fixture f=new Fixture();f.service.rows.get(1).enabled=false;
            yes(has(f.read(),1),"disabled physical cover omitted");});
        test("unrelated disabled virtual display is included",()->{Fixture f=new Fixture();f.add(90,"foreign-disabled",false);
            yes(has(f.read(),90),"unrelated disabled display omitted");});
        test("disabled recorded display id is refused",()->{Fixture f=new Fixture();f.add(f.request.displayId,"retained",false);
            refuse("NOTES_DISPLAY_PRESENT_OR_UNKNOWN",()->f.read());});
        test("disabled recorded name on another id is refused",()->{Fixture f=new Fixture();f.add(90,f.request.displayName,false);
            refuse("NOTES_DISPLAY_PRESENT_OR_UNKNOWN",()->f.read());});
        test("disabled recorded unique identity is refused",()->{Fixture f=new Fixture();f.add(90,"other-name",false).uniqueId="virtual:"+f.request.displayName;
            refuse("NOTES_DISPLAY_PRESENT_OR_UNKNOWN",()->f.read());});
        test("enumerated missing info row is refused",()->{Fixture f=new Fixture();f.service.initial=new int[]{0,1,90};
            refuse("NOTES_DISPLAY_UNKNOWN",()->f.read());});
        test("duplicate initial id is refused",()->{Fixture f=new Fixture();f.service.initial=new int[]{0,1,1};
            refuse("NOTES_DISPLAY_DUPLICATE",()->f.read());});
        test("negative initial id is refused",()->{Fixture f=new Fixture();f.service.initial=new int[]{0,1,-1};
            refuse("NOTES_DISPLAY_UNKNOWN",()->f.read());});
        test("direct row id mismatch is refused",()->{Fixture f=new Fixture();f.add(90,"foreign",true).displayId=91;
            refuse("NOTES_DISPLAY_UNKNOWN",()->f.read());});
        test("membership change during read is refused",()->{Fixture f=new Fixture();f.service.ending=new int[]{0,1,90};
            refuse("NOTES_DISPLAY_CENSUS_CHANGED",()->f.read());});
        test("duplicate ending id is refused",()->{Fixture f=new Fixture();f.service.ending=new int[]{0,1,1};
            refuse("NOTES_DISPLAY_CENSUS_CHANGED",()->f.read());});
        test("enumeration order does not imply membership change",()->{Fixture f=new Fixture();f.service.ending=new int[]{1,0};
            yes(has(f.read(),1),"unchanged membership refused");});
        test("null enumeration is refused",()->{Fixture f=new Fixture();f.service.nullIds=true;
            refuse("NOTES_DISPLAY_CENSUS_BOUND",()->f.read());});
        test("missing display service is refused",()->{Fixture f=new Fixture();ServiceManager.service=null;
            refuse("NOTES_DISPLAY_SERVICE_UNAVAILABLE",()->PersonalNotesDisplayCensusFixture.read(f.manager,f.request));});
        System.out.println(new JSONObject().put("cases",passed.size()+failed.size()).put("assertions",assertions)
                .put("passed",new JSONArray(passed)).put("failed",new JSONArray(failed)).put("phone_operations",0));
        if(!failed.isEmpty())throw new AssertionError("display census failures: "+failed.size());
    }
}
