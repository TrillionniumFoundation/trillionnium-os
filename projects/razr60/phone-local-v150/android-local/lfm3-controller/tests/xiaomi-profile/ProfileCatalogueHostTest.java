package org.trillionnium.hepta.local;

import java.util.*;
import org.json.*;
import org.trillionnium.hepta.background.*;

/** Executes the production catalogue decoder; no process or Android API is called. */
public final class ProfileCatalogueHostTest {
    private static int assertions;
    private static final List<String> cases=new ArrayList<String>();
    private static final int OWNER=10245;
    private static final String REQUEST="12345678-1234-4234-9234-123456789abc";
    private static final String HASH=String.join("",Collections.nCopies(64,"a"));
    interface Work {void run()throws Exception;}
    static void yes(boolean value){assertions++;if(!value)throw new AssertionError("profile catalogue boundary");}
    static void test(String name,Work work)throws Exception{work.run();cases.add(name);}
    static void reject(Work work)throws Exception{try{work.run();}catch(Exception expected){assertions++;return;}throw new AssertionError("invalid catalogue accepted");}
    static ProfileTarget target(String pkg,int user,long serial){
        return new ProfileTarget(new ProfileIdentity(user,serial,0,ProfileIdentity.MANAGED),user*100000+10367,pkg,
                pkg+"/"+(ProfileTarget.XIAOMI.equals(pkg)?"com.xiaomi.shop2.activity.MainActivity":"ctrip.android.view.SplashActivity"),
                ProfileTarget.XIAOMI.equals(pkg)?20261010:1779,Collections.singletonMap("base",HASH),Collections.singleton(HASH));
    }
    static JSONObject receipt(Object...items){return new JSONObject().put("schema","hepta.profile-catalogue.v1")
            .put("owner_uid",OWNER).put("request_id",REQUEST).put("targets",new JSONArray(Arrays.asList(items)));}
    static List<ProfileTarget> decode(JSONObject value)throws Exception{return ProfileCatalogueClient.decode(value.toString(),OWNER,REQUEST);}
    public static void main(String[] args)throws Exception{
        ProfileTarget c=target(ProfileTarget.CTRIP,10,20),x=target(ProfileTarget.XIAOMI,10,20);
        test("two_packages_in_same_user_and_serial_are_distinct",()->{
            List<ProfileTarget> result=decode(receipt(c.wire(),x.wire()));
            yes(result.size()==2&&result.get(0).same(c)&&result.get(1).same(x));
            yes("携程".equals(result.get(0).appLabel())&&"小米商城".equals(result.get(1).appLabel()));
            try{result.clear();throw new AssertionError("mutable result");}catch(UnsupportedOperationException expected){assertions++;}
        });
        test("duplicate_instance_rejected",()->reject(()->decode(receipt(x.wire(),x.wire()))));
        test("duplicate_instance_cannot_hide_different_apk",()->{
            ProfileTarget y=new ProfileTarget(x.profile,x.fullUid,x.packageName,x.component,x.versionCode,
                    Collections.singletonMap("base",String.join("",Collections.nCopies(64,"b"))),x.signerSha256);
            reject(()->decode(receipt(x.wire(),y.wire())));
        });
        test("one_user_cannot_claim_two_serials",()->reject(()->decode(receipt(c.wire(),target(ProfileTarget.XIAOMI,10,21).wire()))));
        test("one_serial_cannot_claim_two_users",()->reject(()->decode(receipt(c.wire(),target(ProfileTarget.XIAOMI,11,20).wire()))));
        test("bounded_four_profiles_two_packages_each",()->{
            List<Object> items=new ArrayList<Object>();for(int user=10;user<14;user++)for(String pkg:ProfileTarget.PACKAGES)items.add(target(pkg,user,user+20).wire());
            yes(decode(receipt(items.toArray())).size()==8);
        });
        test("fifth_profile_rejected_even_with_fewer_than_eight_rows",()->{
            List<Object> items=new ArrayList<Object>();for(int user=10;user<15;user++)items.add(target(ProfileTarget.XIAOMI,user,user+20).wire());
            reject(()->decode(receipt(items.toArray())));
        });
        test("ninth_row_rejected",()->reject(()->decode(receipt(c.wire(),c.wire(),c.wire(),c.wire(),c.wire(),c.wire(),c.wire(),c.wire(),c.wire()))));
        test("owner_mismatch_rejected",()->reject(()->decode(receipt(x.wire()).put("owner_uid",OWNER+1))));
        test("request_mismatch_rejected",()->reject(()->decode(receipt(x.wire()).put("request_id",REQUEST+"0"))));
        test("nonwire_row_rejected",()->reject(()->decode(receipt(7))));
        test("trailing_json_rejected",()->reject(()->ProfileCatalogueClient.decode(receipt(x.wire()).toString()+"{}",OWNER,REQUEST)));
        test("notes_and_arbitrary_packages_still_forbidden",()->{
            reject(()->target("com.motorola.stylus",10,20));reject(()->target("com.example.any",10,20));
            yes(!ProfileTarget.supportsPackage("com.motorola.stylus"));
        });
        test("empty_catalogue_has_no_substitution",()->yes(decode(receipt()).isEmpty()));
        System.out.println(new JSONObject().put("all_pass",true).put("cases",cases.size()).put("assertions",assertions)
                .put("case_names",new JSONArray(cases)).put("actual_production_decoder",true).put("phone_actions",0));
    }
}
