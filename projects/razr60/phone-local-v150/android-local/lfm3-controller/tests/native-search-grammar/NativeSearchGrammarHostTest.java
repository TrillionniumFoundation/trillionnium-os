package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.json.JSONObject;

/** Uses the actual Session constructor/offer() supplied by the calling fixture.
 * This helper never constructs an Offer, Frame, PhoneObservation, or authority. */
final class NativeSearchGrammarHostTest {
    private final List<String> cases=new ArrayList<String>();
    private int assertions;
    private void begin(String name){if(cases.contains(name))throw new AssertionError("duplicate case");cases.add(name);}
    private void check(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
    private interface Checked {void run()throws Exception;}
    private void denied(Checked action,String why)throws Exception{
        boolean failed=false;try{action.run();}catch(IllegalArgumentException|IllegalStateException expected){failed=true;}
        check(failed,why);
    }
    private void immutable(Checked action,String why)throws Exception{
        boolean failed=false;try{action.run();}catch(UnsupportedOperationException expected){failed=true;}
        check(failed,why);
    }
    private static String sha(String text)throws Exception{
        StringBuilder out=new StringBuilder(64);
        for(byte b:MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)))
            out.append(String.format(Locale.ROOT,"%02x",b&255));
        return out.toString();
    }
    private static void write(Path file,String value)throws Exception{
        Files.write(file,value.getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE);
    }

    static Map<String,Object> verify(final NativeSearchSession.Offer offer,
            final TaskAuthorization.Frame frame,Path output)throws Exception{
        NativeSearchGrammarHostTest t=new NativeSearchGrammarHostTest();
        Files.createDirectory(output);
        t.begin("real_offer_gate_entry_and_exact_new_schema");
        DecisionGrammar g=DecisionGrammar.createNativeSearchAuthorized(offer,frame);
        t.check(NativeSearchDecision.SCHEMA.equals(g.schema)&&"hepta.native-search-intent.v1".equals(g.schema),"explicit separate schema");
        t.check(g.authorization==frame,"the supplied actual Gate frame is retained");
        t.check(g.observationId.equals(offer.planning.id)&&g.currentPackage.equals(offer.planning.packageName),"exact actual planning identity");

        t.begin("singleton_native_intent_without_legacy_capabilities");
        t.check(g.actions.equals(Collections.singletonList(NativeSearchDecision.ACTION)),"only native.open_search");
        t.check(g.scrollDirections.isEmpty()&&g.submitNodes.isEmpty()&&g.fixedIntentTargets.isEmpty(),"no other effect domains");
        t.check(g.doneStatuses.isEmpty()&&!g.successAllowed,"no terminal or success domain");
        t.check(g.appLabels==null&&g.targets.labels.isEmpty(),"no invented app label or node label");
        t.check(g.targets.observationId.equals(g.observationId)&&g.targets.packageName.equals(g.currentPackage),"empty label metadata uses actual planning identity");
        t.check(!g.allowsSubmit("n1")&&!g.allowsScroll("n1","down"),"old capability predicates remain false");

        t.begin("published_domains_are_immutable");
        t.immutable(()->g.actions.add("click"),"action list immutable");
        t.immutable(()->g.doneStatuses.add("success"),"terminal set immutable");
        t.immutable(()->g.submitNodes.add("n1"),"submit set immutable");
        t.immutable(()->g.scrollDirections.put("n1",Arrays.asList("down")),"scroll map immutable");
        t.immutable(()->g.fixedIntentTargets.put("notes.create",null),"fixed intent map immutable");
        t.immutable(()->g.targets.labels.put("n1","搜索"),"target label projection immutable");

        t.begin("actual_utf8_hash_and_repeat_generation");
        t.check(g.sha256.equals(sha(g.text))&&g.text.getBytes(StandardCharsets.UTF_8).length<=65536,"hash is actual bounded emitted bytes");
        DecisionGrammar again=DecisionGrammar.createNativeSearchAuthorized(offer,frame);
        t.check(g.text.equals(again.text)&&g.sha256.equals(again.sha256),"same actual Offer generates deterministic grammar");

        t.begin("compact_format_preserves_typed_authority_and_domains");
        DecisionGrammar compact=g.compactReasonAndWhitespace();
        t.check(compact.schema.equals(g.schema)&&compact.authorization==g.authorization,"compact copy preserves schema and Gate frame");
        t.check(compact.targets==g.targets&&compact.actions==g.actions&&compact.doneStatuses==g.doneStatuses,"compact copy preserves immutable domain objects");
        t.check(compact.scrollDirections==g.scrollDirections&&compact.submitNodes==g.submitNodes
                &&compact.fixedIntentTargets==g.fixedIntentTargets&&compact.appLabels==null&&!compact.successAllowed,"compact has no domain widening");
        t.check(compact.sha256.equals(sha(compact.text))&&!compact.sha256.equals(g.sha256),"compact hashes its own actual format subset");

        t.begin("missing_offer_and_frame_are_rejected");
        t.denied(()->DecisionGrammar.createNativeSearchAuthorized(null,frame),"no missing Offer");
        t.denied(()->DecisionGrammar.createNativeSearchAuthorized(offer,null),"no missing authority");
        t.denied(()->DecisionGrammar.createNativeSearchAuthorized(null,null),"no default protocol");

        t.begin("actual_new_parser_preserves_the_selected_intent");
        String raw="{\"reason\":\"host grammar fixture\",\"action\":\"native.open_search\",\"observation_id\":\""
                +g.observationId+"\",\"package\":\""+g.currentPackage+"\",\"role_id\":\""+offer.planning.role.roleId+"\"}";
        NativeSearchDecision parsed=NativeSearchDecision.parse(raw);
        t.check(parsed.observationId.equals(g.observationId)&&parsed.packageName.equals(g.currentPackage)
                &&parsed.roleId.equals(offer.planning.role.roleId),"actual strict parser carries the exact selected role");

        t.begin("old_parser_cannot_execute_new_protocol");
        boolean oldSchemaDenied=false,newSchemaDenied=false;
        try{ActionDecision.parse(raw,ObservedTargetLabels.ACTION_SCHEMA);}catch(ActionDecision.InvalidActionException expected){oldSchemaDenied=true;}
        try{ActionDecision.parse(raw,NativeSearchDecision.SCHEMA);}catch(ActionDecision.InvalidActionException expected){newSchemaDenied=true;}
        t.check(oldSchemaDenied&&newSchemaDenied,"new action and schema have no old ActionDecision dispatcher fallback");

        t.begin("old_label_click_and_done_remain_separate_protocols");
        ObservedTargetLabels labels=ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,g.observationId,g.currentPackage,
                Collections.singletonMap("n1",""));
        DecisionGrammar legacy=DecisionGrammar.create(g.observationId,g.currentPackage,Collections.<String>emptySet(),
                Collections.singleton("n1"),Collections.<String>emptySet(),Collections.<String,ObservedScrollActions>emptyMap(),labels);
        t.check(!legacy.schema.equals(g.schema)&&legacy.actions.contains("click")&&!legacy.actions.contains(NativeSearchDecision.ACTION),"old grammar is unchanged and separate");
        boolean legacyDenied=false;
        try{NativeSearchDecision.parse("{\"reason\":\"legacy click\",\"action\":\"click\",\"observation_id\":\""
                +g.observationId+"\",\"package\":\""+g.currentPackage+"\",\"node_label\":\"\",\"node_id\":\"n1\"}");}
        catch(ActionDecision.InvalidActionException expected){legacyDenied=true;}
        t.check(legacyDenied,"native intent parser cannot consume a legacy click");

        write(output.resolve("native-search.gbnf"),g.text);
        write(output.resolve("native-search-compact.gbnf"),compact.text);
        write(output.resolve("legacy.gbnf"),legacy.text);
        Map<String,Object> report=new LinkedHashMap<String,Object>();
        report.put("schema","hepta.native-search-grammar-host.v1");report.put("all_pass",true);
        report.put("case_names",t.cases);report.put("cases",t.cases.size());report.put("assertions",t.assertions);
        report.put("observation_id",g.observationId);report.put("package",g.currentPackage);report.put("role_id",offer.planning.role.roleId);
        report.put("protocol_schema",g.schema);report.put("normal_sha256",g.sha256);report.put("compact_sha256",compact.sha256);
        report.put("legacy_sha256",legacy.sha256);report.put("actual_offer_factory_called",true);
        report.put("offer_created_by_this_helper",false);report.put("phone_tested",false);
        report.put("native_grammar_engine_tested",false);report.put("model_inference_tested",false);
        write(output.resolve("JAVA-RESULT.json"),new JSONObject(report).toString(2)+"\n");
        return Collections.unmodifiableMap(report);
    }
}
