package org.trillionnium.hepta.local;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import org.json.JSONObject;

/** Incremental synthetic-only semantics checks over the already reviewed public
 * complete detail fixture. Does not invoke the 83-case suite or private replay. */
public final class DetailPriceSemanticsHostTest {
    private static final String SLOT="0/0/10/1";
    private static final NativeAppGoal GOAL=NativeAppGoal.parse("在小米商城查询AX3000T价格",NativeAppGoal.XIAOMI_PACKAGE);
    private static final List<Map<String,Object>> RESULTS=new ArrayList<Map<String,Object>>();
    private static int assertions;
    private static Class<?> fixtureClass;
    private static Constructor<?> fixtureConstructor;
    private static Method rowMethod,frameMethod,textMethod;
    private interface Mutation { void apply(Object fixture)throws Exception; }
    private static void check(boolean value,String message){assertions++;if(!value)throw new AssertionError(message);}
    @SuppressWarnings("unchecked")
    private static Map<String,Object> row(Object fixture,String path)throws Exception{
        return (Map<String,Object>)rowMethod.invoke(fixture,path);
    }
    private static void text(Object fixture,String path,String text)throws Exception{textMethod.invoke(fixture,path,text);}
    private static void description(Object fixture,String path,String value)throws Exception{
        row(fixture,path).put("description",value);row(fixture,path).put("label",value);
    }
    private static Map<String,Object> entry(String name,boolean accepted,Collection<String> missing){
        Map<String,Object> r=new LinkedHashMap<String,Object>();
        r.put("name",name);r.put("quote_accepted",accepted);r.put("missing",new ArrayList<String>(missing));
        r.put("synthetic_counterfactual",true);return r;
    }
    private static void one(String name,Mutation mutation,boolean shouldAccept,boolean baseline)throws Exception{
        Object fixture=fixtureConstructor.newInstance();mutation.apply(fixture);
        NativeAppEvidence.Frame frame=(NativeAppEvidence.Frame)frameMethod.invoke(fixture);
        NativeXiaomiProductPage.Page parsed=NativeXiaomiProductPage.inspect(GOAL,frame);
        boolean accepted=parsed.quote!=null;
        boolean expected=shouldAccept||baseline;
        check(accepted==expected,name+" expected quote="+expected+" actual="+accepted+" "+parsed.missing);
        check(parsed.clickIds.isEmpty()&&parsed.editValues.isEmpty()&&parsed.purposes.isEmpty(),name+" never grants action");
        if(accepted){
            check("159".equals(parsed.quote.amountDecimal)&&"199".equals(parsed.quote.comparisonAmountDecimal),name+" preserves description amount");
            check(Boolean.FALSE.equals(parsed.quote.evidence().get("promotions_deducted_from_amount")),name+" no deduction");
        }else check(!parsed.missing.isEmpty(),name+" explicit parser refusal");
        Map<String,Object> result=entry(name,accepted,parsed.missing);
        result.put("expected_after_fix",shouldAccept?"accept":"reject");
        result.put("baseline_bug_observed",baseline&&!shouldAccept&&accepted);
        RESULTS.add(result);
    }
    public static void main(String[] args)throws Exception{
        if(args.length!=3)throw new IllegalArgumentException("fixture output baseline-or-current");
        boolean baseline="baseline".equals(args[2]);
        if(!baseline&&!"current".equals(args[2]))throw new IllegalArgumentException("exact mode");
        Field publicFixture=DetailMirrorHostTest.class.getDeclaredField("publicFixture");publicFixture.setAccessible(true);
        publicFixture.set(null,new JSONObject(new String(Files.readAllBytes(Paths.get(args[0])),StandardCharsets.UTF_8)));
        fixtureClass=Class.forName("org.trillionnium.hepta.local.DetailMirrorHostTest$Fixture");
        fixtureConstructor=fixtureClass.getDeclaredConstructor();fixtureConstructor.setAccessible(true);
        rowMethod=fixtureClass.getDeclaredMethod("row",String.class);rowMethod.setAccessible(true);
        frameMethod=fixtureClass.getDeclaredMethod("frame");frameMethod.setAccessible(true);
        textMethod=fixtureClass.getDeclaredMethod("text",String.class,String.class);textMethod.setAccessible(true);

        one("original_ranking_one_and_known_conditions",f->{},true,baseline);
        one("ordinary_review_text_is_not_price",f->text(f,SLOT,"评价1"),true,baseline);
        one("ordinary_value_word_is_not_price",f->text(f,SLOT,"性价比高"),true,baseline);
        one("existing_installment_reduction_preserved",f->text(f,SLOT,"分期最高减20元"),true,baseline);
        one("coupon_price_without_currency",f->text(f,SLOT,"券后价99"),false,baseline);
        one("independent_original_price_without_currency",f->text(f,SLOT,"原价199"),false,baseline);
        one("independent_current_price_without_currency",f->description(f,SLOT,"现价99"),false,baseline);
        one("monthly_payment_description_without_currency",f->description(f,SLOT,"月供12.3"),false,baseline);
        one("price_caption_and_amount_split",f->{text(f,"0/0/10/0","售价");text(f,SLOT,"99");},false,baseline);
        one("installment_period_amount_without_currency",f->text(f,SLOT,"分12期每期12.3"),false,baseline);
        one("label_only_coupon_price",f->row(f,SLOT).put("label","券后价99"),false,baseline);
        one("label_only_monthly_payment",f->row(f,SLOT).put("label","月供12.3"),false,baseline);
        one("label_only_currency_amount",f->row(f,SLOT).put("label","￥99"),false,baseline);
        one("label_only_price_caption",f->row(f,SLOT).put("label","售价"),false,baseline);

        Map<String,Object> report=new LinkedHashMap<String,Object>();
        report.put("schema","hepta.detail-price-semantic-increment.v1");
        report.put("all_pass",true);report.put("mode",args[2]);report.put("cases",RESULTS.size());report.put("assertions",assertions);
        report.put("results",RESULTS);report.put("fixture_origin","peer public synthetic 104-node/60-projection shape");
        report.put("private_originals_read",false);report.put("phone_operations",0);report.put("android_runtime",false);
        report.put("business_completion_verified",false);report.put("existing_83_case_suite_rerun",false);
        Path output=Paths.get(args[1]);Files.write(output,ObservationCaptureEvidence.canonicalBytes(report));
        System.out.println("PASS "+args[2]+" cases="+RESULTS.size()+" assertions="+assertions);
    }
}
