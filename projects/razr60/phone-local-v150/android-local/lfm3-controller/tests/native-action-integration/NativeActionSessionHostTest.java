package org.trillionnium.hepta.local;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.json.JSONObject;

/** Real Session/TCG/Domain with the unchanged provider Harness. Its original
 * XML year roundtrip supplies history; task/lease/model/installed/outcomes are
 * explicit host doubles. No platform action or replacement Frame is created. */
final class NativeActionSessionHostTest {
    interface Work {void run()throws Exception;}
    static String sha(String value){return NativeAppEvidence.hash(value);}
    static String id(String value){return sha(value).substring(0,32);}
    static void yes(boolean value,String reason){IntegrationChecks.yes(value,reason);}
    static void rejects(Work work,String reason)throws Exception{IntegrationChecks.rejects(()->work.run(),reason);}
    static void one(String name,Work work)throws Exception{IntegrationChecks.one(name,()->work.run());}
    static NativeAppProviderHostTest.Harness harness(String name)throws Exception{return new NativeAppProviderHostTest.Harness(name);}
    static ActionDecision begin(NativeAppProviderHostTest.Harness h,String purpose)throws Exception{
        ActionDecision a=h.action(purpose);h.step++;h.lastRun=id(h.task+":guard-model:"+h.step);h.time+=10;
        h.owner.check(a,h.lastRun);h.session.beforeModelAction(h.step,a,h.lastRun,h.time);return a;
    }
    static NativeAppSession.ActionGuard guard(NativeAppProviderHostTest.Harness h,ActionDecision a)throws Exception{
        return h.session.actionGuard(a,h.lastRun,h.frame.observationId,h.time,h.time+8000);
    }
    static void outcome(NativeAppProviderHostTest.Harness h,ActionDecision a,boolean accepted,boolean dispatched,boolean stale)throws Exception{
        h.session.modelActionOutcome(a,h.lastRun,accepted,dispatched,stale,sha("host-durable-outcome:"+h.lastRun),++h.time);
    }
    static Map<?,?> progress(NativeAppSession session){return (Map<?,?>)session.evidence().get("progress");}
    static List<?> queryDates(NativeAppSession session){return (List<?>)progress(session).get("explicit_query_attempt_dates");}
    static ActionDecision sameValue(ActionDecision a)throws Exception{
        return ActionDecision.parse(new JSONObject().put("action",a.action).put("package",a.packageName)
                .put("observation_id",a.observationId).put("node_id",a.nodeId).put("node_label",a.nodeLabel).toString(),a.actionSchema);
    }
    static NativeAppSession freshSession(NativeAppProviderHostTest.Harness h,NativeAppSession.Journal journal)throws Exception{
        return new NativeAppSession(h.task,h.owner,h.selected,h.session.installed,h.session.selectionSha,h.session.generation,h.session.displayId,
                ()->{if(!h.installedCurrent)throw new IllegalStateException("host installed replacement");},journal);
    }
    public static void main(String[] args)throws Exception{
        run(Paths.get(args[0]),Paths.get(args[2]));
        IntegrationChecks.finish(Paths.get(args[1]),"hepta.native-action-session-guard-host.v1",
                "Actual complete Session/TCG/Domain and original provider/year/home factories. Model, installed identity, frame metadata, journal and outcomes are explicit host doubles; no Android/currentness/effect/SDK/phone/business qualification.");
    }
    static void run(Path source,Path scratch)throws Exception{
        NativeAppProviderHostTest.fixtures=source.resolve("tests/native-app-provider/fixtures");
        NativeResourceHomeHostTest.fixture=source.resolve("tests/native-app-provider/fixtures/ctrip-cold-home-grid.json");
        NativeResourceHomeHostTest.privateRoot=scratch;
        one("query_guard_uses_actual_year_roundtrip_and_same_original_attempt",()->{
            NativeAppProviderHostTest.Harness h=harness("query-original");h.year();NativeAppDomain before=h.session.domain();
            List<?> transitions=(List<?>)progress(h.session).get("transitions");yes(transitions.size()==2,"actual date-control and Back transitions");
            ActionDecision a=begin(h,"query_observed_form");int writes=h.records.size();NativeAppSession.ActionGuard g=guard(h,a);
            yes(g!=null&&g.action==a&&g.frame==h.frame&&g.targetNode==h.frame.byId.get(a.nodeId),"same original action/frame/target objects");
            yes(g.selection==h.selected&&g.target==h.selected.target&&g.goal==h.selected.target.nativeGoal&&g.authorization==h.owner,"same Selection/goal/auth objects");
            yes(g.installed==h.session.installed&&h.session.domain()==before,"no replacement installed descriptor or Domain");
            yes(queryDates(h.session).equals(Collections.singletonList("2026-11-14")),"one reservation for observed14, not OWNER17");
            yes(g.queryHistory.get("calendar_year_round_trip").equals(transitions.get(1)),"proof is the original actual roundtrip");
            yes("2026-11-14".equals(g.queryHistory.get("date"))&&Boolean.TRUE.equals(g.queryHistory.get("original_query_budget_already_consumed")),"same proved date and prior budget");
            yes(h.records.size()==writes&&progress(h.session).get("last_query_date")==null,"guard adds no journal/query/observation");
            g.requireOpen(a,h.lastRun,h.time);g.verifyInstalled();
            yes(g.identity.get("origin_observation_id").equals(h.frame.observationId)&&g.identity.get("installed_set_sha256").equals(h.session.installed.apkSetSha256),"original observation and complete installed set");
        });
        one("owner_date_alone_cannot_issue_query_or_guard",()->{
            NativeAppProviderHostTest.Harness h=harness("no-year");h.observe("form17.xml");
            yes(h.target("query_observed_form")==null&&h.target("inspect_departure_year")!=null,"correct initial date is not proof of year");
            String query=null;for(NativeAppEvidence.Node n:h.frame.nodes)if(n.viewId!=null&&n.viewId.endsWith(":id/bt_submit_inquire"))query=n.id;
            yes(query!=null,"actual query widget present");
            ActionDecision a=ActionDecision.parse(new JSONObject().put("action","click").put("package",h.frame.packageName).put("observation_id",h.frame.observationId)
                    .put("node_id",query).put("node_label",h.frame.byId.get(query).label).toString(),ActionDecision.IME_ACTION_SCHEMA);
            rejects(()->h.session.beforeModelAction(1,a,id("no-year-run"),h.time+1),"unproved query cannot enter original Attempt");
            rejects(()->h.session.actionGuard(a,id("no-year-run"),h.frame.observationId,h.time+1,h.time+8001),"no in-flight Attempt means no guard");
        });
        one("guard_requires_successful_original_attempt_journal",()->{
            NativeAppProviderHostTest.Harness h=harness("journal-order");h.observe("form14.xml");ActionDecision a=h.action("inspect_departure_year");
            rejects(()->h.session.actionGuard(a,id("unissued"),h.frame.observationId,h.time,h.time+8000),"no model attempt");
            NativeAppSession s=freshSession(h,(leaf,value)->{if(leaf.startsWith("native-app-attempt-"))throw new java.io.IOException("host durable journal failure");});
            s.observed(h.frame);String run=id("journal-failed");
            IntegrationChecks.ioRejects(()->s.beforeModelAction(1,a,run,h.time),"original journal exception propagates");
            rejects(()->s.actionGuard(a,run,h.frame.observationId,h.time,h.time+8000),"failed journal cannot grant guard");
        });
        identityCases();lifecycleCases();resourceCases();
    }
    static void identityCases()throws Exception{
        one("equal_value_reparsed_action_is_not_original_private_attempt",()->{
            NativeAppProviderHostTest.Harness h=harness("reparsed-action");h.observe("form14.xml");ActionDecision a=begin(h,"inspect_departure_year"),copy=sameValue(a);
            yes(a!=copy&&a.nodeId.equals(copy.nodeId),"different ActionDecision with equal JSON");
            rejects(()->h.session.actionGuard(copy,h.lastRun,h.frame.observationId,h.time,h.time+8000),"same action object required");
            NativeAppSession.ActionGuard g=guard(h,a);rejects(()->g.requireOpen(copy,h.lastRun,h.time),"worker also binds original object");
        });
        one("foreign_model_run_or_original_observation_is_refused",()->{
            NativeAppProviderHostTest.Harness h=harness("run-observation");h.observe("form14.xml");ActionDecision a=begin(h,"inspect_departure_year");
            rejects(()->h.session.actionGuard(a,id("foreign-run"),h.frame.observationId,h.time,h.time+8000),"different model run");
            rejects(()->h.session.actionGuard(a,h.lastRun,id("foreign-observation"),h.time,h.time+8000),"different original observation");
            NativeAppSession.ActionGuard g=guard(h,a);rejects(()->g.requireOpen(a,id("foreign-run"),h.time),"worker run binding");
        });
        one("original_worker_budget_is_not_extended_or_backdated",()->{
            NativeAppProviderHostTest.Harness h=harness("budget");h.observe("form14.xml");ActionDecision a=begin(h,"inspect_departure_year");
            rejects(()->h.session.actionGuard(a,h.lastRun,h.frame.observationId,h.time-1,h.time+7999),"guard predates original attempt");
            rejects(()->h.session.actionGuard(a,h.lastRun,h.frame.observationId,h.time,h.time+8001),"no ninth second");
            rejects(()->h.session.actionGuard(a,h.lastRun,h.frame.observationId,h.time,h.time),"empty interval");
            NativeAppSession.ActionGuard g=guard(h,a);rejects(()->g.requireOpen(a,h.lastRun,h.time-1),"clock before issue");
            rejects(()->g.requireOpen(a,h.lastRun,h.time+8000),"deadline exclusive");
        });
        one("one_guard_per_original_query_attempt",()->{
            NativeAppProviderHostTest.Harness h=harness("duplicate-guard");h.year();ActionDecision a=begin(h,"query_observed_form");NativeAppSession.ActionGuard g=guard(h,a);
            rejects(()->guard(h,a),"guard cannot be reissued to renew query permission");
            yes(queryDates(h.session).size()==1&&g.evidence().get("state").equals(Integer.valueOf(0)),"one original reservation remains");
        });
        one("actual_installed_verifier_is_retained_for_worker_recheck",()->{
            NativeAppProviderHostTest.Harness h=harness("installed");h.observe("form14.xml");ActionDecision a=begin(h,"inspect_departure_year");NativeAppSession.ActionGuard g=guard(h,a);
            g.verifyInstalled();h.installedCurrent=false;rejects(()->g.verifyInstalled(),"actual bound installed verifier replacement");
            yes(g.installed==h.session.installed,"descriptor cannot be replaced to pass verifier");
        });
        one("captured_query_history_and_identity_are_deep_immutable",()->{
            NativeAppProviderHostTest.Harness h=harness("immutable");h.year();ActionDecision a=begin(h,"query_observed_form");NativeAppSession.ActionGuard g=guard(h,a);
            IntegrationChecks.immutable(()->g.identity.put("owner_sha256",sha("other")),"owner identity immutable");
            IntegrationChecks.immutable(()->g.queryHistory.clear(),"query history immutable");
            Map<?,?> roundtrip=(Map<?,?>)g.queryHistory.get("calendar_year_round_trip");
            IntegrationChecks.immutable(()->roundtrip.clear(),"nested actual history immutable");
            yes(g.historySha.equals(NativeAppEvidence.fingerprint(g.queryHistory)),"digest of actual immutable captured history");
        });
    }
    static void lifecycleCases()throws Exception{
        one("claim_is_single_use_and_close_revokes_claimed_effect",()->{
            NativeAppProviderHostTest.Harness h=harness("claim");h.observe("form14.xml");ActionDecision a=begin(h,"inspect_departure_year");NativeAppSession.ActionGuard g=guard(h,a);
            g.claim(a,h.lastRun,h.time);g.requireClaimed();
            rejects(()->g.claim(a,h.lastRun,h.time),"no second effect CAS");rejects(()->g.requireOpen(a,h.lastRun,h.time),"claimed is not an open permission");
            g.close();rejects(()->g.requireClaimed(),"close after claim revokes effect entry");rejects(()->g.claim(a,h.lastRun,h.time),"closed cannot reopen");
        });
        one("close_before_claim_and_expired_claim_cannot_enter",()->{
            NativeAppProviderHostTest.Harness h=harness("close");h.observe("form14.xml");ActionDecision a=begin(h,"inspect_departure_year");NativeAppSession.ActionGuard g=guard(h,a);
            rejects(()->g.claim(a,h.lastRun,h.time+8000),"no effect at deadline");g.close();
            rejects(()->g.claim(a,h.lastRun,h.time),"close wins original atomic state");yes(g.evidence().get("state").equals(Integer.valueOf(2)),"closed state retained");
        });
        one("stale_outcome_closes_guard_without_refunding_query_budget",()->{
            NativeAppProviderHostTest.Harness h=harness("stale-reservation");h.year();ActionDecision a=begin(h,"query_observed_form");NativeAppSession.ActionGuard g=guard(h,a);
            outcome(h,a,false,false,true);rejects(()->g.requireOpen(a,h.lastRun,h.time),"outcome closes guard");
            h.observe("form14.xml");yes(h.target("query_observed_form")==null,"original same-date query remains consumed");
            yes(queryDates(h.session).equals(Collections.singletonList("2026-11-14")),"no duplicate reservation or refund");
            yes(progress(h.session).get("last_query_date")==null&&!h.session.domain().resultReady,"stale query never proves a result");
        });
        one("accepted_query_still_requires_original_outcome_and_next_page",()->{
            NativeAppProviderHostTest.Harness h=harness("query-result");h.year();ActionDecision a=begin(h,"query_observed_form");NativeAppSession.ActionGuard g=guard(h,a);
            g.claim(a,h.lastRun,h.time);g.requireClaimed();yes(progress(h.session).get("last_query_date")==null,"claim itself is no query result");
            outcome(h,a,true,true,false);rejects(()->g.requireClaimed(),"outcome closes the original claim");
            yes(progress(h.session).get("last_query_date")==null,"dispatch needs parsed result transition");
            h.observe("result14.xml");yes("2026-11-14".equals(progress(h.session).get("last_query_date")),"actual result14 closes reserved query14");
            yes(queryDates(h.session).size()==1&&!h.session.domain().resultReady,"non-target14 cannot complete requested17");
        });
        one("worker_revalidation_cannot_advance_session_before_outcome",()->{
            NativeAppProviderHostTest.Harness h=harness("inflight-frame");h.year();ActionDecision a=begin(h,"query_observed_form");NativeAppSession.ActionGuard g=guard(h,a);NativeAppDomain before=h.session.domain();
            NativeAppEvidence.Frame fresh=h.frame("form14.xml");rejects(()->h.session.observed(fresh),"new frame cannot advance in-flight Session");
            yes(h.session.domain()==before&&g.frame==before.frame,"original Domain/frame remain bound");g.requireOpen(a,h.lastRun,g.issued);
        });
        one("session_retirement_and_invalid_outcome_revoke_worker_guard",()->{
            NativeAppProviderHostTest.Harness h=harness("retire");h.observe("form14.xml");ActionDecision a=begin(h,"inspect_departure_year");NativeAppSession.ActionGuard g=guard(h,a);
            h.session.retire();rejects(()->g.claim(a,h.lastRun,h.time),"session retirement revokes guard");
            NativeAppProviderHostTest.Harness z=harness("invalid");z.observe("form14.xml");ActionDecision b=begin(z,"inspect_departure_year");NativeAppSession.ActionGuard q=guard(z,b);
            outcome(z,b,false,true,false);rejects(()->q.claim(b,z.lastRun,z.time),"invalid outcome closes guard");rejects(()->z.session.domain(),"invalid task cannot be repaired by comparator");
        });
        one("unsupported_wait_and_calendar_back_keep_original_null_guard",()->{
            NativeAppProviderHostTest.Harness h=harness("wait");h.observe("form14.xml");
            ActionDecision a=ActionDecision.parse(new JSONObject().put("action","wait").put("package",h.frame.packageName).put("observation_id",h.frame.observationId).put("duration_ms",100).toString(),ActionDecision.IME_ACTION_SCHEMA);
            h.step++;h.time+=10;h.lastRun=id("wait-run");h.owner.check(a,h.lastRun);h.session.beforeModelAction(h.step,a,h.lastRun,h.time);
            yes(guard(h,a)==null,"wait gains no click permission");outcome(h,a,true,false,false);
            NativeAppProviderHostTest.Harness z=harness("back");z.observe("form14.xml");z.perform("inspect_departure_year","calendar14.xml");ActionDecision b=begin(z,"return_from_calendar");
            yes(guard(z,b)==null,"Back uses original path");
        });
    }
    static void resourceCases()throws Exception{
        one("actual_cold_home_empty_label_keeps_original_resource_identity",()->{
            NativeResourceHomeHostTest.Env e=new NativeResourceHomeHostTest.Env(NativeResourceHomeHostTest.raw());ActionDecision a=e.click("n15","",e.frame.observationId);String run=id("home-guard");
            e.owner.check(a,run);e.session.beforeModelAction(1,a,run,120);int writes=e.journalWrites;
            NativeAppSession.ActionGuard g=e.session.actionGuard(a,run,e.frame.observationId,120,8120);
            yes(g!=null&&NativeActionSnapshotCheck.OPEN.equals(g.purpose)&&g.targetNode==e.frame.byId.get("n15"),"same original resource target");
            yes(g.targetNode.label.isEmpty()&&g.selection==e.selection&&g.frame==e.frame,"no fabricated visible label or frame");
            String full=ObservedImeEnter.UNKNOWN.bindFreshness(ObservedScrollActions.observed(Collections.<String>emptyList()).bindFreshness(g.targetNode.signature),false,null);NativeActionSnapshotCheck.Intent intent=g.intent(full);
            yes(sha(full).equals(intent.refSha256)&&!intent.refSha256.equals(g.targetNode.signature),"full Service ref is separate from retained tree signature");
            yes(e.journalWrites==writes&&!e.domain().resultReady,"guard creates no query or result");
        });
        one("equal_looking_replaced_selection_cannot_bind_new_session",()->{
            NativeResourceHomeHostTest.Env e=new NativeResourceHomeHostTest.Env(NativeResourceHomeHostTest.raw());
            BackgroundSession.Selection replacement=new BackgroundSession.Selection(e.target);
            rejects(()->new NativeAppSession(e.task,e.owner,replacement,e.session.installed,e.session.selectionSha,e.session.generation,7,
                    ()->{},(leaf,value)->{}),"private authorization requires same Selection object");
        });
        one("invented_cold_home_label_is_refused_before_guard",()->{
            NativeResourceHomeHostTest.Env e=new NativeResourceHomeHostTest.Env(NativeResourceHomeHostTest.raw());ActionDecision bad=e.click("n15","机票",e.frame.observationId);
            rejects(()->e.session.beforeModelAction(1,bad,id("invented-label"),120),"unnamed original resource cannot be relabelled");
        });
    }
}
