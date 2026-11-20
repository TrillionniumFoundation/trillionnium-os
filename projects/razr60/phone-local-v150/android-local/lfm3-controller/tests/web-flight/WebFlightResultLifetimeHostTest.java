package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.DateTimeException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/** Synthetic typed-carrier inputs only. There is no website parser, real flight
 * record, model inference, Android service, native dispatch, or phone operation. */
public final class WebFlightResultLifetimeHostTest {
    private static final String DATE="2026-11-17",URL="https://m.csair.com/booking_new/";
    private static final String GENERATION="22345678-1234-1234-1234-123456789012";
    private static final List<String> names=new ArrayList<String>();
    private static int assertions;
    private interface Work{void run()throws Exception;}
    private static void check(boolean condition,String why){assertions++;if(!condition)throw new AssertionError(why);}
    private static void test(String name,Work work)throws Exception{work.run();names.add(name);}
    private static void rejects(Work work)throws Exception{
        boolean refused=false;
        try{work.run();}catch(IllegalArgumentException|DateTimeException expected){refused=true;}
        check(refused,"invalid result state must be rejected");
    }
    private static void immutable(Work work)throws Exception{
        boolean refused=false;try{work.run();}catch(UnsupportedOperationException expected){refused=true;}
        check(refused,"published result evidence must be immutable");
    }
    private static String hex(char c,int n){char[] v=new char[n];Arrays.fill(v,c);return new String(v);}
    private static WebFlightResult.Scope scope(int change){
        return new WebFlightResult.Scope(hex(change==0?'2':'1',32),hex(change==1?'3':'2',64),
                hex(change==2?'4':'3',64),hex(change==3?'5':'4',64),hex(change==4?'6':'5',64),
                change==5?"32345678-1234-1234-1234-123456789012":GENERATION,
                change==6?"synthetic-helper-2":"synthetic-helper-1",change==7?8:7,change==8?20:19);
    }
    private static WebFlightResult.Frame before(){
        return new WebFlightResult.Frame(scope(-1),hex('6',32),hex('7',64),hex('8',64),URL,7,100,110);
    }
    private static WebFlightResult.Frame after(){
        return new WebFlightResult.Frame(scope(-1),hex('9',32),hex('a',64),hex('b',64),URL,8,130,140);
    }
    private static WebFlightResult.Query query(WebFlightResult.Lifetime life){
        WebFlightResult.Query query=new WebFlightResult.Query(life,before(),hex('c',32),"n1003","北京","上海",DATE,true,true,false,true,112,120);
        query.observed(after());return query;
    }
    private static Map<String,Object> proof(){
        Map<String,Object> value=new LinkedHashMap<String,Object>();
        value.put("synthetic_carrier_only",true);value.put("real_dom_native_field_proof",false);return value;
    }
    private static WebFlightResult.Row row(String path,String number,String amount){
        return new WebFlightResult.Row(path,number,"合成出发机场","合成到达机场",DATE,"10:00",DATE,"12:00",
                amount,"CNY","not_stated_on_current_page",null,"not_stated_on_current_page",null,proof());
    }
    private static WebFlightResult.Page page(WebFlightResult.Frame frame,String from,String to,String date,List<WebFlightResult.Row> rows){
        return new WebFlightResult.Page(frame,"synthetic-host-carrier.v1",WebFlightResult.FLIGHTS,from,to,date,rows,null,proof());
    }
    private static WebFlightResult.Page page(WebFlightResult.Frame frame){
        return page(frame,"北京","上海",DATE,Collections.singletonList(row("0/0/0","CZ1234","488")));
    }
    public static void main(String[] args)throws Exception{
        check(args.length==1,"create-only result path required");
        test("accepted_native_query_binds_exact_current_typed_page",()->{
            WebFlightResult.Query q=query(new WebFlightResult.Lifetime());WebFlightResult.Frame f=after();
            WebFlightResult r=WebFlightResult.bind(q,f,page(f));check(r.matches(q,f),"exact current result");
            check(Boolean.FALSE.equals(r.evidence().get("business_verified"))
                    &&Boolean.FALSE.equals(r.evidence().get("grants_tool_authority"))
                    &&Boolean.FALSE.equals(r.evidence().get("server_response_payload_verified"))
                    &&Boolean.FALSE.equals(r.evidence().get("final_native_and_cleanup_gates_verified")),"read-only scope is explicit");
        });
        test("reservation_rejection_uncertainty_and_stale_dispatch_cannot_authorize",()->{
            boolean[][] combinations={{false,true,false,true},{true,false,false,true},{true,true,true,true},{true,true,false,false}};
            for(boolean[] flags:combinations)rejects(()->new WebFlightResult.Query(new WebFlightResult.Lifetime(),before(),hex('c',32),
                    "n1003","北京","上海",DATE,flags[0],flags[1],flags[2],flags[3],112,120));
        });
        test("dispatch_must_follow_the_bound_prequery_capture",()->{
            rejects(()->new WebFlightResult.Query(new WebFlightResult.Lifetime(),before(),hex('c',32),"n1003","北京","上海",DATE,true,true,false,true,109,120));
            rejects(()->new WebFlightResult.Query(new WebFlightResult.Lifetime(),before(),hex('c',32),"n1003","北京","上海",DATE,true,true,false,true,121,120));
        });
        for(int i=0;i<9;i++){
            final int changed=i;
            test("scope_field_"+i+"_cannot_reuse_dispatched_query",()->{
                WebFlightResult.Frame f=new WebFlightResult.Frame(scope(changed),hex('9',32),hex('a',64),hex('b',64),URL,8,130,140);
                rejects(()->WebFlightResult.bind(query(new WebFlightResult.Lifetime()),f,page(f)));
            });
        }
        test("prequery_or_inflight_document_is_not_a_result",()->{
            WebFlightResult.Query q=query(new WebFlightResult.Lifetime());
            rejects(()->WebFlightResult.bind(q,before(),page(before())));
            WebFlightResult.Frame early=new WebFlightResult.Frame(scope(-1),hex('9',32),hex('a',64),hex('b',64),URL,8,119,130);
            rejects(()->WebFlightResult.bind(q,early,page(early)));
            WebFlightResult.Frame epoch=new WebFlightResult.Frame(scope(-1),hex('9',32),hex('a',64),hex('b',64),URL,6,130,140);
            rejects(()->WebFlightResult.bind(q,epoch,page(epoch)));
        });
        test("query_form_hash_and_original_observation_cannot_be_relabelled_results",()->{
            WebFlightResult.Query q=query(new WebFlightResult.Lifetime());
            WebFlightResult.Frame sameDom=new WebFlightResult.Frame(scope(-1),hex('9',32),hex('a',64),before().dom,URL,8,130,140);
            rejects(()->WebFlightResult.bind(q,sameDom,page(sameDom)));
            WebFlightResult.Frame sameObservation=new WebFlightResult.Frame(scope(-1),before().observation,hex('a',64),hex('b',64),URL,8,130,140);
            rejects(()->WebFlightResult.bind(q,sameObservation,page(sameObservation)));
        });
        test("every_capture_coordinate_is_bound_not_just_url_and_route",()->{
            WebFlightResult.Query q=query(new WebFlightResult.Lifetime());WebFlightResult.Frame original=after();
            WebFlightResult r=WebFlightResult.bind(q,original,page(original));
            WebFlightResult.Frame[] changed={
                new WebFlightResult.Frame(scope(-1),hex('d',32),hex('a',64),hex('b',64),URL,8,130,140),
                new WebFlightResult.Frame(scope(-1),hex('9',32),hex('d',64),hex('b',64),URL,8,130,140),
                new WebFlightResult.Frame(scope(-1),hex('9',32),hex('a',64),hex('d',64),URL,8,130,140),
                new WebFlightResult.Frame(scope(-1),hex('9',32),hex('a',64),hex('b',64),URL+"#synthetic-other",8,130,140),
                new WebFlightResult.Frame(scope(-1),hex('9',32),hex('a',64),hex('b',64),URL,9,130,140),
                new WebFlightResult.Frame(scope(-1),hex('9',32),hex('a',64),hex('b',64),URL,8,131,140),
                new WebFlightResult.Frame(scope(-1),hex('9',32),hex('a',64),hex('b',64),URL,8,130,141)};
            for(WebFlightResult.Frame f:changed){check(!r.matches(q,f),"changed capture cannot read old result");rejects(()->WebFlightResult.bind(q,f,page(original)));}
        });
        test("displayed_route_and_date_must_match_the_actual_dispatched_query",()->{
            WebFlightResult.Query q=query(new WebFlightResult.Lifetime());WebFlightResult.Frame f=after();
            rejects(()->WebFlightResult.bind(q,f,page(f,"天津","上海",DATE,Collections.singletonList(row("0/0","CZ1234","488")))));
            rejects(()->WebFlightResult.bind(q,f,page(f,"北京","杭州",DATE,Collections.singletonList(row("0/0","CZ1234","488")))));
            WebFlightResult.Page otherDate=new WebFlightResult.Page(f,"synthetic-host-carrier.v1",WebFlightResult.NONE,"北京","上海","2026-11-18",
                    Collections.<WebFlightResult.Row>emptyList(),"合成明确无航班提示",proof());
            rejects(()->WebFlightResult.bind(q,f,otherDate));
        });
        test("same_serialized_query_identifier_is_not_the_same_runtime_query",()->{
            WebFlightResult.Lifetime life=new WebFlightResult.Lifetime();WebFlightResult.Query a=query(life),b=query(new WebFlightResult.Lifetime());
            check(a.id.equals(b.id),"same audit id is intentionally reproducible");
            WebFlightResult r=WebFlightResult.bind(a,after(),page(after()));check(!r.matches(b,after()),"object capability cannot be reconstructed by its hash");
            rejects(()->query(life));
        });
        test("recapture_keeps_semantics_but_requires_new_exact_result_binding",()->{
            WebFlightResult.Query q=query(new WebFlightResult.Lifetime());WebFlightResult.Frame a=after();
            WebFlightResult.Frame b=new WebFlightResult.Frame(scope(-1),hex('d',32),hex('e',64),hex('b',64),URL,8,150,160);
            WebFlightResult ra=WebFlightResult.bind(q,a,page(a));q.observed(b);WebFlightResult rb=WebFlightResult.bind(q,b,page(b));
            check(ra.semanticSha().equals(rb.semanticSha()),"same displayed fields stable across a fresh read");
            check(!ra.matches(q,b)&&rb.matches(q,b),"old exact result cannot follow a new observation");
            check(!ra.matches(q,a),"new publication also retires the old domain's own result authority");
            WebFlightResult changed=WebFlightResult.bind(q,b,page(b,"北京","上海",DATE,Collections.singletonList(row("0/0/0","CZ1234","489"))));
            check(!rb.semanticSha().equals(changed.semanticSha()),"a price change invalidates semantic comparison");
            check(!rb.matches(q,b),"changed result semantics retire the prior same-observation publication");
        });
        test("fresh_same_native_frame_readback_keeps_only_matching_result_semantics",()->{
            WebFlightResult.Query q=query(new WebFlightResult.Lifetime());WebFlightResult.Frame first=after();
            WebFlightResult r=WebFlightResult.bind(q,first,page(first));
            WebFlightResult.Frame fresh=new WebFlightResult.Frame(scope(-1),first.observation,first.state,first.dom,first.url,first.epoch,150,160);
            q.observed(fresh);rejects(()->WebFlightResult.bind(q,first,page(first)));
            check(!r.matches(q,first),"fresh capture suspends old readiness until an independently bound result exists");
            WebFlightResult checked=WebFlightResult.bind(q,fresh,page(fresh));
            check(r.matches(q,first)&&checked.matches(q,fresh),"same exact result permits the separate final recapture check");
            check(r.evidence().get("query_publication_sequence").equals(checked.evidence().get("query_publication_sequence")),"fresh recapture alone does not claim new publication");
        });
        test("changed_dom_with_same_native_frame_suspends_old_result_until_valid_provider_rebind",()->{
            WebFlightResult.Query q=query(new WebFlightResult.Lifetime());WebFlightResult.Frame first=after();
            WebFlightResult r=WebFlightResult.bind(q,first,page(first));
            WebFlightResult.Frame fresh=new WebFlightResult.Frame(scope(-1),first.observation,first.state,hex('f',64),first.url,first.epoch,150,160);
            q.observed(fresh);
            check(!r.matches(q,first),"DOM-only change without a provider cannot retain completion authority");
            rejects(()->WebFlightResult.bind(q,fresh,page(first)));
            rejects(()->WebFlightResult.bind(q,fresh,page(fresh,"北京","杭州",DATE,Collections.singletonList(row("0/0/0","CZ1234","488")))));
            check(!r.matches(q,first),"failed or wrong-frame provider does not restore old readiness");
            WebFlightResult checked=WebFlightResult.bind(q,fresh,page(fresh));
            check(r.matches(q,first)&&checked.matches(q,fresh),"same result semantics restore only after exact current-frame provider binding");
            q.observed(fresh);
            check(!r.matches(q,first)&&!checked.matches(q,fresh),"even a repeated observation call cannot manufacture provider proof");
        });
        test("new_navigation_retires_old_result_even_without_a_new_provider",()->{
            WebFlightResult.Query q=query(new WebFlightResult.Lifetime());WebFlightResult.Frame first=after();
            WebFlightResult r=WebFlightResult.bind(q,first,page(first));
            WebFlightResult.Frame newer=new WebFlightResult.Frame(scope(-1),hex('d',32),hex('e',64),hex('b',64),URL,9,150,160);
            q.observed(newer);check(!r.matches(q,first),"old page cannot trigger close after navigation");
            rejects(()->WebFlightResult.bind(q,first,page(first)));
        });
        test("combined_record_failure_cannot_restore_suspended_result_authority",()->{
            WebFlightResult.Query q=query(new WebFlightResult.Lifetime());WebFlightResult.Frame first=after();
            WebFlightResult r=WebFlightResult.bind(q,first,page(first));
            WebFlightResult.Frame fresh=new WebFlightResult.Frame(scope(-1),first.observation,first.state,first.dom,first.url,first.epoch,150,160);
            q.observed(fresh);
            Map<String,Object> large=new LinkedHashMap<String,Object>();for(int i=0;i<26000;i++)large.put("proof_"+i,i);
            WebFlightResult.Row largeRow=new WebFlightResult.Row("0/0/0","CZ1234","合成出发机场","合成到达机场",DATE,"10:00",DATE,"12:00",
                    "488","CNY","not_stated_on_current_page",null,"not_stated_on_current_page",null,large);
            WebFlightResult.Page largePage=new WebFlightResult.Page(fresh,"synthetic-host-carrier.v1",WebFlightResult.FLIGHTS,
                    "北京","上海",DATE,Collections.singletonList(largeRow),null,large);
            check(largePage.semanticSha.equals(r.semanticSha()),"only combined proof size differs from the previously verified displayed fields");
            rejects(()->WebFlightResult.bind(q,fresh,largePage));
            check(!r.matches(q,first),"failed complete record construction never republishes old authority");
            WebFlightResult checked=WebFlightResult.bind(q,fresh,page(fresh));
            check(r.matches(q,first)&&checked.matches(q,fresh),"only a successful complete immutable result can restore exact recheck authority");
        });
        test("empty_page_is_not_an_explicit_no_flights_result",()->{
            rejects(()->new WebFlightResult.Page(after(),"synthetic-host-carrier.v1",WebFlightResult.FLIGHTS,"北京","上海",DATE,Collections.<WebFlightResult.Row>emptyList(),null,proof()));
            rejects(()->new WebFlightResult.Page(after(),"synthetic-host-carrier.v1",WebFlightResult.NONE,"北京","上海",DATE,Collections.<WebFlightResult.Row>emptyList(),null,proof()));
            rejects(()->new WebFlightResult.Page(after(),"synthetic-host-carrier.v1",WebFlightResult.NONE,"北京","上海",DATE,Collections.singletonList(row("0/0","CZ1234","488")),"合成无航班",proof()));
            WebFlightResult.Page none=new WebFlightResult.Page(after(),"synthetic-host-carrier.v1",WebFlightResult.NONE,"北京","上海",DATE,Collections.<WebFlightResult.Row>emptyList(),"合成明确无航班提示",proof());
            check(WebFlightResult.bind(query(new WebFlightResult.Lifetime()),after(),none).evidence().get("displayed_flight_count").equals(0),"only explicit provider no-flight carrier qualifies");
        });
        test("duplicate_record_or_dom_path_is_ambiguous",()->{
            rejects(()->page(after(),"北京","上海",DATE,Arrays.asList(row("0/0","CZ1234","488"),row("0/0","CZ1235","488"))));
            rejects(()->page(after(),"北京","上海",DATE,Arrays.asList(row("0/0","CZ1234","488"),row("0/1","CZ1234","488"))));
        });
        test("complete_airport_flight_datetime_price_and_currency_fields_required",()->{
            String[][] variants={{"","CZ1234","488","CNY",DATE,"10:00",DATE,"12:00"},{"合成机场","","488","CNY",DATE,"10:00",DATE,"12:00"},
                {"合成机场","CZ1234","0","CNY",DATE,"10:00",DATE,"12:00"},{"合成机场","CZ1234","488","",DATE,"10:00",DATE,"12:00"},
                {"合成机场","CZ1234","488","CNY","11-17","10:00",DATE,"12:00"},{"合成机场","CZ1234","488","CNY",DATE,"25:00",DATE,"12:00"},
                {"合成机场","CZ1234","488","CNY",DATE,"10:00","2026-11-16","12:00"},{"合成机场","CZ1234","488","CNY",DATE,"10:00",DATE,"09:00"}};
            for(String[] v:variants)rejects(()->new WebFlightResult.Row("0/0",v[1],v[0],"合成到达机场",v[4],v[5],v[6],v[7],v[2],v[3],"not_stated_on_current_page",null,"not_stated_on_current_page",null,proof()));
        });
        test("unreported_tax_is_not_zero_or_empty_displayed_text",()->{
            rejects(()->new WebFlightResult.Row("0/0","CZ1234","合成出发机场","合成到达机场",DATE,"10:00",DATE,"12:00","488","CNY","displayed","","not_stated_on_current_page",null,proof()));
            rejects(()->new WebFlightResult.Row("0/0","CZ1234","合成出发机场","合成到达机场",DATE,"10:00",DATE,"12:00","488","CNY","not_stated_on_current_page","0","not_stated_on_current_page",null,proof()));
            check(row("0/0","CZ1234","488").modelView().get("taxes_raw")==null,"unknown raw tax remains null");
        });
        test("bounded_deep_evidence_is_copied_and_immutable",()->{
            List<Object> nested=new ArrayList<Object>();nested.add("original");Map<String,Object> p=proof();p.put("nested",nested);
            WebFlightResult.Row row=new WebFlightResult.Row("0/0","CZ1234","合成出发机场","合成到达机场",DATE,"10:00",DATE,"12:00","488","CNY","not_stated_on_current_page",null,"not_stated_on_current_page",null,p);
            List<WebFlightResult.Row> rows=new ArrayList<WebFlightResult.Row>();rows.add(row);
            WebFlightResult.Page pg=new WebFlightResult.Page(after(),"synthetic-host-carrier.v1",WebFlightResult.FLIGHTS,"北京","上海",DATE,rows,null,p);
            nested.set(0,"changed");rows.clear();p.clear();
            WebFlightResult r=WebFlightResult.bind(query(new WebFlightResult.Lifetime()),after(),pg);
            @SuppressWarnings("unchecked") Map<String,Object> stored=(Map<String,Object>)r.evidence().get("provider_page_proof");
            check(((List<?>)stored.get("nested")).get(0).equals("original")&&pg.rows.size()==1,"caller mutations cannot rewrite evidence");
            immutable(()->r.evidence().put("business_verified",true));immutable(()->pg.rows.clear());
            immutable(()->((List<?>)stored.get("nested")).clear());immutable(()->r.modelView().clear());
            Map<String,Object> cyclic=proof();cyclic.put("self",cyclic);
            rejects(()->new WebFlightResult.Page(after(),"synthetic-host-carrier.v1",WebFlightResult.NONE,"北京","上海",DATE,Collections.<WebFlightResult.Row>emptyList(),"合成无航班",cyclic));
        });
        test("retirement_invalidates_old_result_and_all_late_bindings",()->{
            WebFlightResult.Lifetime life=new WebFlightResult.Lifetime();WebFlightResult.Query q=query(life);
            WebFlightResult r=WebFlightResult.bind(q,after(),page(after()));life.retire();life.retire();
            check(!r.matches(q,after()),"retired result is not current even on original frame");
            rejects(()->WebFlightResult.bind(q,after(),page(after())));rejects(()->query(life));
        });
        test("late_provider_thread_cannot_publish_after_retirement",()->{
            WebFlightResult.Lifetime life=new WebFlightResult.Lifetime();WebFlightResult.Query q=query(life);
            CountDownLatch started=new CountDownLatch(1),release=new CountDownLatch(1);
            AtomicReference<Object> result=new AtomicReference<Object>();
            Thread worker=new Thread(()->{started.countDown();try{
                if(!release.await(3,TimeUnit.SECONDS))throw new AssertionError("test release timeout");
                result.set(WebFlightResult.bind(q,after(),page(after())));
            }catch(Throwable error){result.set(error);}},"synthetic-late-flight-provider");
            worker.start();check(started.await(3,TimeUnit.SECONDS),"worker reached test boundary");life.retire();release.countDown();worker.join(3000);
            check(!worker.isAlive()&&result.get() instanceof IllegalArgumentException,"late completion is rejected after the real retirement boundary");
        });
        test("other_origin_insecure_url_and_userinfo_cannot_be_result_scope",()->{
            for(String value:new String[]{"http://m.csair.com/","https://example.com/","https://user@m.csair.com/","https://m.csair.com:444/"})
                rejects(()->new WebFlightResult.Frame(scope(-1),hex('9',32),hex('a',64),hex('b',64),value,8,130,140));
        });
        test("bounded_model_view_preserves_unenumerated_scope",()->{
            List<WebFlightResult.Row> rows=new ArrayList<WebFlightResult.Row>();
            for(int i=0;i<33;i++)rows.add(row("0/"+i,"CZ"+(1000+i),"488"));
            rejects(()->page(after(),"北京","上海",DATE,rows));rows.remove(32);
            WebFlightResult r=WebFlightResult.bind(query(new WebFlightResult.Lifetime()),after(),page(after(),"北京","上海",DATE,rows));
            check(((List<?>)r.modelView().get("flights")).size()==8&&r.modelView().get("additional_records_in_private_evidence").equals(24),"bounded model result");
            check(Boolean.FALSE.equals(r.modelView().get("all_available_flights_enumerated")),"current rows never imply all inventory");
        });
        StringBuilder out=new StringBuilder("{\n  \"schema\":\"hepta.flight-result-lifetime-host.v1\",\n  \"all_pass\":true,\n  \"cases\":")
                .append(names.size()).append(",\n  \"assertions\":").append(assertions)
                .append(",\n  \"synthetic_typed_carriers_only\":true,\n  \"actual_provider_executed\":false,\n  \"actual_results_verified\":false,\n  \"phone_actions\":0,\n  \"names\":[");
        for(int i=0;i<names.size();i++){if(i>0)out.append(',');out.append('"').append(names.get(i)).append('"');}
        out.append("]\n}\n");Files.write(Paths.get(args[0]),out.toString().getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
        System.out.println("PASS flight result lifetime: "+names.size()+" cases / "+assertions+" assertions; synthetic carriers only");
    }
}
