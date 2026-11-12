#!/usr/bin/env python3
"""Run existing Web host gates against the exact Main56 source.
The old80/43/13 assertions are retained; Composition appends only10 terminal
and17 homepage-stability cases. Actual counts come from the child reports.
No SDK, Android build, core101 pass, signing, phone or model call is required.
"""
import gzip,hashlib,json,os,signal,stat,subprocess,sys,time,traceback
from pathlib import Path,PurePosixPath

CONFIG=json.loads("{\"schema\":\"hepta.main56-existing-web-regression-stage-config.v1\",\"root\":\"/home/alex/hepta-local-007f-20261111/v56-main-web-regression-host-r2\",\"source_root\":\"/home/alex/hepta-local-007f-20261111/v56-main-core101-materialized-host-r2/source\",\"materialized_root\":\"/home/alex/hepta-local-007f-20261111/v56-main-core101-materialized-host-r2\",\"decoded_input\":{\"bytes\":260128,\"sha256\":\"3687b09656e60a808ebdce1430951e04741581e9ddd0d2faa7f5c36220ed24b7\",\"git_blob_sha\":\"1153d7e55c4051ecf6e4c018defe43d26ff51fd2\"},\"aggregate\":{\"git\":\"0803dec4b6acc359b810bb79ca6fdd01ada69a8c\",\"bytes\":1427055,\"sha256\":\"c1cc7cc16eef4c3a34131ee719101a69db080b76e72c98f03248036fc6fd628f\",\"inventory_sha256\":\"d87173f40a5f2793e077408674f2f8a24b8152d74f5fd01cdcdf5fd403ebd386\"},\"inventory\":{\"bytes\":103795,\"sha256\":\"ca24673843908c7f9343c949af64b8393e69ce53605128782036ae9ce9d1f46e\"},\"java\":{\"path\":\"/home/alex/razr-local-ai-20261109-82d1243e/host-jdk17/extracted/usr/lib/jvm/java-17-openjdk-amd64/bin/java\",\"bytes\":14544,\"sha256\":\"bb70208200cb6538b877d80478141194a716edb591f4910ec106589291e99196\"},\"javac\":{\"path\":\"/home/alex/razr-local-ai-20261109-82d1243e/host-jdk17/extracted/usr/lib/jvm/java-17-openjdk-amd64/bin/javac\",\"bytes\":14592,\"sha256\":\"2aaf03d13aeb80b8269696f2dcd9f4937d7366bbc68f91fdc703cf157e8f39c4\"},\"json\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v55-helper6-p4-public-inputs-r1/host-json/json-20240303.jar\",\"bytes\":78332,\"sha256\":\"3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed\"},\"orgjson_ready\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v55-helper6-p4-public-inputs-r1/ORGJSON-READY.json\",\"bytes\":1289,\"sha256\":\"37f3b1790fce237f6339cab159015da7937e6517cc4a97f4dc16443c74e01d7b\"},\"expected_gates\":[{\"name\":\"evidence80\",\"class_name\":\"org.trillionnium.hepta.local.WebFlightEvidenceHostTest\",\"prior_file\":\"WEB-RESULT.json\",\"cases\":80,\"assertions\":92,\"schema\":\"hepta.web-flight-evidence-host-cases.v1\"},{\"name\":\"composition43\",\"class_name\":\"org.trillionnium.hepta.local.WebTaskCompositionHostTest\",\"prior_file\":\"COMPOSITION-RESULT.json\",\"cases\":70,\"assertions\":178,\"schema\":\"hepta.v55-web-task-composition-host.v1\"},{\"name\":\"calendar13\",\"class_name\":\"org.trillionnium.hepta.local.WebCalendarNativeHostTest\",\"prior_file\":\"CALENDAR-NATIVE-RESULT.json\",\"cases\":13,\"assertions\":1001,\"schema\":\"hepta.csair-calendar-native-host.v1\"}],\"case_name_mapping\":{\"v3_receipt_and_real_composition\":\"v4_receipt_and_real_composition\",\"duplicate_native_resource_id_blocks_even_disabled\":\"duplicate_native_card_description_blocks_even_disabled\",\"duplicate_dom_id_blocks_product_link\":\"ambiguous_observed_region_blocks_product_link\"},\"key\":\"007f-v56-main-existing-web-regression-host-r2-geometry-map\",\"prior_web\":{\"root\":\"/home/alex/hepta-local-007f-20261111/v55-main-web-regression-host-r2\",\"result\":{\"bytes\":41316,\"sha256\":\"c64027a42b69cc828a7d612f609c14b4b3e643a4662f1ca473840deda096406b\",\"git_blob_sha\":\"e104e5d5f8c49ffccbf494e0a4dc431733d93a5a\"},\"stage\":{\"bytes\":38346,\"sha256\":\"ede9eb863619a67f9c17187360ea38e39472fd96eb4bc53c8928d75303cf3c71\",\"git_blob_sha\":\"f2bf0e695199c53c2d4b959153b47e78b7396aaf\"},\"packet\":{\"bytes\":161563,\"sha256\":\"6b2c8f192b00e95feae521e657e2bc9552b1cbf251510ef75818f5884c0cf9e3\",\"git_blob_sha\":\"7c98d42f3ea3babad09e7a47eb5121cec9a1cc7c\"}},\"source_file_count\":595,\"fixture_count\":6,\"production_java_count\":44,\"compilation_unit_count\":52,\"added_case_names\":[\"terminal_verified_snapshot_survives_only_normal_known_close\",\"terminal_unclaimed_unstable_or_unverified_result_never_freezes\",\"terminal_final_frame_identity_changes_are_rejected\",\"terminal_final_native_node_changes_are_rejected\",\"terminal_closed_callback_identity_is_exact\",\"terminal_unknown_abort_and_late_close_never_recover_success\",\"terminal_clear_rebind_and_late_observation_invalidate_proof\",\"terminal_requires_actual_owner_scope_cleanup_and_native_parent_facts\",\"terminal_tokens_are_gate_local_and_consumed_once\",\"terminal_flight_without_results_provider_stays_unverified\",\"flight_home_actual_two_dom_carousel_only_difference\",\"flight_home_dom_target_label_change_rejected\",\"flight_home_dom_non_carousel_geometry_rejected\",\"flight_home_dom_extra_slider_semantics_rejected\",\"flight_home_dom_vertical_or_nonuniform_motion_rejected\",\"flight_home_dom_visible_modal_in_both_reads_rejected\",\"flight_home_dom_metadata_or_membership_change_rejected\",\"flight_home_actual_retained_native_ad_only_change\",\"flight_home_retained_ordinal_shift_preserves_path_binding\",\"flight_home_retained_target_semantics_change_rejected\",\"flight_home_synthetic_full_native_same_overlap_accepted\",\"flight_home_full_native_target_change_rejected\",\"flight_home_full_native_ancestor_or_focus_change_rejected\",\"flight_home_full_native_ad_content_change_rejected\",\"flight_home_full_native_new_overlap_rejected\",\"flight_home_full_native_missing_ancestor_rejected\",\"flight_home_full_native_foreign_package_or_target_path_rejected\"],\"prior_expected_gates\":[{\"name\":\"evidence80\",\"class_name\":\"org.trillionnium.hepta.local.WebFlightEvidenceHostTest\",\"prior_file\":\"WEB-RESULT.json\",\"cases\":80,\"assertions\":92,\"schema\":\"hepta.web-flight-evidence-host-cases.v1\"},{\"name\":\"composition43\",\"class_name\":\"org.trillionnium.hepta.local.WebTaskCompositionHostTest\",\"prior_file\":\"COMPOSITION-RESULT.json\",\"cases\":43,\"assertions\":59,\"schema\":\"hepta.v55-web-task-composition-host.v1\"},{\"name\":\"calendar13\",\"class_name\":\"org.trillionnium.hepta.local.WebCalendarNativeHostTest\",\"prior_file\":\"CALENDAR-NATIVE-RESULT.json\",\"cases\":13,\"assertions\":1001,\"schema\":\"hepta.csair-calendar-native-host.v1\"}],\"prior_failed56\":{\"root\":\"/home/alex/hepta-local-007f-20261111/v56-main-web-regression-host-r1\",\"result\":{\"bytes\":29724,\"sha256\":\"f9bf137d294e385c6cd85987a10ba682fdb9bb8415fa51a005e5ff871914eec4\",\"git_blob_sha\":\"30962e2f30d7b0309aaacd44d67e795e436752ee\"},\"stage\":{\"bytes\":124611,\"sha256\":\"e315704ec4f11f6e37cafc158dcbd831ad713efc376289100cdc48d35826eba6\",\"git_blob_sha\":\"7bf26d7df0b20c2079695980303ff2237add2465\"},\"packet\":{\"bytes\":255644,\"sha256\":\"2bdec480247b39ab2a0ec566d0999919d8723d52f55bc81f9df7beb9b1129ee5\",\"git_blob_sha\":\"bb76eb9c16289058b5d2297edb9eb7d51118c69b\"},\"composition_stderr\":{\"bytes\":1012,\"sha256\":\"242466b11bebf08dc48246b949fb506dc8bde71bba0c7be798c0fa98d6b0ef75\",\"git_blob_sha\":\"b437fd9854666141f78911df0a7b53c9de376165\"},\"aggregate\":{\"git\":\"660335b7f19f519af4cfd168ebee186f1a4693b9\",\"bytes\":1416544,\"sha256\":\"38baa995ee76520e1a9ff7a14baf51afdbd4f1af53f747ce7a0d114ef4809c90\",\"inventory_sha256\":\"71ad8ef4ea1023850c950282d57bcae3e73877e5e6a7ad582b58951e1ba7001e\"}}}")
PACKET_DELTA=json.loads("{\"schema\":\"hepta.main56-web-fixture-exact-derivation.v1\",\"base\":{\"bytes\":161563,\"sha256\":\"6b2c8f192b00e95feae521e657e2bc9552b1cbf251510ef75818f5884c0cf9e3\",\"git_blob_sha\":\"7c98d42f3ea3babad09e7a47eb5121cec9a1cc7c\"},\"result\":{\"bytes\":260128,\"sha256\":\"3687b09656e60a808ebdce1430951e04741581e9ddd0d2faa7f5c36220ed24b7\",\"git_blob_sha\":\"1153d7e55c4051ecf6e4c018defe43d26ff51fd2\"},\"schema_before\":\"hepta.main55-web-regression-v4-fixture-successor.v1\",\"schema_after\":\"hepta.main56-web-regression-fixture-successor.v1\",\"current_aggregate_before\":{\"git\":\"d3bf59d91e5681fd5991c4bfef8587ba9a7b2a2d\",\"bytes\":1320157,\"sha256\":\"66ac069a14b64db51d9f2d09bf52acc6a8d9dc93484f8c21e3c3276ac31c2f06\",\"inventory_sha256\":\"5e445cbdd8ef7322e98ed97174b39b42d89cc757369e4ac5bd79d308faaf70c4\"},\"current_aggregate_after\":{\"git\":\"0803dec4b6acc359b810bb79ca6fdd01ada69a8c\",\"bytes\":1427055,\"sha256\":\"c1cc7cc16eef4c3a34131ee719101a69db080b76e72c98f03248036fc6fd628f\",\"inventory_sha256\":\"d87173f40a5f2793e077408674f2f8a24b8152d74f5fd01cdcdf5fd403ebd386\"},\"composition\":{\"path\":\"tests/web-flight/WebTaskCompositionHostTest.java\",\"before\":{\"bytes\":35210,\"sha256\":\"a1dab97ae5a81eb3d5133068f66ff2057b7d4ad6afc1deff895406af9a7b82b2\",\"git_blob_sha\":\"3731b53306137dcb9b2b2f0acea31fa07fa9f25f\"},\"after\":{\"bytes\":53410,\"sha256\":\"35c0702df7ff94e261dadbc219bc4afe7ddba8f72cc2cd5ec23f8acb0771f68e\",\"git_blob_sha\":\"d1052b460b32020a5e7bfb061623d9447a13e597\"},\"ordered_replacements\":[{\"before\":\"    public static void main(String[] argv)throws Exception{\\n\",\"after\":\"    // These lifecycle inputs are explicit host doubles. The provider/domain,\\n    // TCG, immutable snapshot, identity checks and one-shot transitions are real.\\n    // This is not an authenticated Binder CLOSE or a native-worker execution.\\n    private static NotesCompletionEvidence.Frame terminalFrame()throws Exception{\\n        PhoneObservation f=detailFrame();List<NotesCompletionEvidence.Node> nodes=new ArrayList<NotesCompletionEvidence.Node>();\\n        for(PhoneObservation.Node n:f.nodes){\\n            String label=n.label();\\n            if(n.text.trim().isEmpty()&&n.description.trim().isEmpty()&&(n.childText.truncated||!\\\"derived\\\".equals(n.childText.status)))label=\\\"\\\";\\n            nodes.add(new NotesCompletionEvidence.Node(n.id,n.packageName,n.text,label,n.viewId,n.inputTextSha256,\\n                    new int[]{n.bounds.left,n.bounds.top,n.bounds.right,n.bounds.bottom},n.editable,n.clickable,n.scrollable,\\n                    n.enabled,n.password,n.childText,n.observedAppTreeSignature));\\n        }\\n        return new NotesCompletionEvidence.Frame(f.id,f.packageName,f.windowId,7,f.backgroundGeneration,1,true,false,nodes);\\n    }\\n    private static final class TerminalFixture {\\n        final TaskAuthorization authorization=TaskAuthorization.parse(OWNER);\\n        final TaskCompletionGate gate=new TaskCompletionGate(TASK,OWNER,authorization);\\n        final Object lease=new Object();final WebTaskDomain domain;final NotesCompletionEvidence.Frame frame;\\n        final String binding;TaskCompletionGate.WebCloseAttempt close;boolean claimVerified;\\n        TerminalFixture(WebTaskDomain domain,boolean claim,boolean stable)throws Exception{\\n            this.domain=domain;frame=terminalFrame();binding=(String)domain.evidence().get(\\\"binding_sha256\\\");\\n            gate.observed(frame);gate.bindWebDomain(domain);\\n            if(claim)claimVerified=gate.successClaim(1,RUN,frame,stable).verified;\\n        }\\n        void retire(){close=gate.beginWebClose(lease,domain,TASK,binding,\\\"normal\\\");gate.clearWebDomain();}\\n        boolean known(String bad){\\n            return gate.webCloseKnown(close,lease,\\\"task\\\".equals(bad)?repeat(\\\"e\\\",32):TASK,\\n                    \\\"binding\\\".equals(bad)?repeat(\\\"e\\\",64):binding,\\\"status\\\".equals(bad)?\\\"recovered_retired\\\":\\\"closed\\\",\\n                    \\\"instance\\\".equals(bad)?\\\"different-instance\\\":domain.instance,domain.epoch+(\\\"epoch\\\".equals(bad)?1:0),\\n                    domain.displayId+(\\\"display\\\".equals(bad)?1:0),domain.windowId+(\\\"window\\\".equals(bad)?1:0),\\n                    \\\"callback_sha\\\".equals(bad)?\\\"unverified\\\":repeat(\\\"a\\\",64));\\n        }\\n        TaskCompletionGate.Check finish(String bad,NotesCompletionEvidence.Frame current){\\n            TaskAuthorization.Frame owner=authorization.bind(\\\"owner_task\\\".equals(bad)?repeat(\\\"e\\\",32):TASK).frame();\\n            if(\\\"owner\\\".equals(bad))owner=TaskAuthorization.parse(OWNER).bind(TASK).frame();\\n            if(\\\"no_owner\\\".equals(bad))owner=null;\\n            return gate.terminalWebCheck(\\\"lease\\\".equals(bad)?new Object():lease,current,owner,\\n                    \\\"step\\\".equals(bad)?2:1,\\\"model_run\\\".equals(bad)?repeat(\\\"e\\\",32):RUN,\\n                    !\\\"model_success\\\".equals(bad),!\\\"cleanup\\\".equals(bad),!\\\"helper\\\".equals(bad),!\\\"background\\\".equals(bad),\\n                    !\\\"scope\\\".equals(bad),\\\"cancelled\\\".equals(bad),!\\\"not_started\\\".equals(bad),!\\\"not_exited\\\".equals(bad),\\n                    \\\"exit\\\".equals(bad)?1:0,!\\\"receipt\\\".equals(bad),\\\"worker_task\\\".equals(bad)?repeat(\\\"e\\\",32):TASK,\\n                    \\\"worker_generation\\\".equals(bad)?\\\"missing\\\":repeat(\\\"b\\\",32),\\\"worker_sha\\\".equals(bad)?\\\"missing\\\":repeat(\\\"c\\\",64));\\n        }\\n    }\\n    private static TerminalFixture closedFixture(WebTaskDomain linked)throws Exception{\\n        TerminalFixture f=new TerminalFixture(linked,true,true);\\n        if(!f.claimVerified)throw new IllegalStateException(\\\"synthetic real-provider prerequisite\\\");\\n        f.retire();if(!f.known(\\\"\\\"))throw new IllegalStateException(\\\"synthetic ordinary-close prerequisite\\\");return f;\\n    }\\n    private static NotesCompletionEvidence.Frame changedFrame(NotesCompletionEvidence.Frame f,String field,List<NotesCompletionEvidence.Node> nodes){\\n        return new NotesCompletionEvidence.Frame(\\\"observation\\\".equals(field)?repeat(\\\"e\\\",32):f.observationId,\\n                \\\"package\\\".equals(field)?\\\"org.synthetic.other\\\":f.packageName,f.windowId+(\\\"window\\\".equals(field)?1:0),\\n                f.displayId+(\\\"display\\\".equals(field)?1:0),\\\"generation\\\".equals(field)?\\\"32345678-1234-1234-1234-123456789012\\\":f.backgroundGeneration,\\n                \\\"type\\\".equals(field)?2:f.windowType,!\\\"metadata\\\".equals(field)&&f.metadataObserved,\\n                \\\"truncated\\\".equals(field)||f.nodesTruncated,nodes);\\n    }\\n    private static NotesCompletionEvidence.Node changedNode(NotesCompletionEvidence.Node n,String field){\\n        ObservedChildText.Result child=n.childText;\\n        if(\\\"child\\\".equals(field))child=new ObservedChildText.Result(\\\"changed child\\\",\\\"derived\\\",false,1,Collections.<ObservedChildText.Source>emptyList());\\n        if(\\\"visited\\\".equals(field))child=new ObservedChildText.Result(child.text,child.status,child.truncated,child.visited+1,child.sources);\\n        return new NotesCompletionEvidence.Node(\\\"id\\\".equals(field)?\\\"n999\\\":n.id,\\n                \\\"package\\\".equals(field)?\\\"org.synthetic.other\\\":n.packageName,\\\"text\\\".equals(field)?n.text+\\\" changed\\\":n.text,\\n                \\\"label\\\".equals(field)?n.label+\\\" changed\\\":n.label,\\\"view\\\".equals(field)?n.viewId+\\\" changed\\\":n.viewId,\\n                \\\"input\\\".equals(field)?repeat(\\\"e\\\",64):n.inputTextSha256,\\n                new int[]{n.left+(\\\"left\\\".equals(field)?1:0),n.top+(\\\"top\\\".equals(field)?1:0),\\n                        n.right+(\\\"right\\\".equals(field)?1:0),n.bottom+(\\\"bottom\\\".equals(field)?1:0)},\\n                \\\"editable\\\".equals(field)?!n.editable:n.editable,\\\"clickable\\\".equals(field)?!n.clickable:n.clickable,\\n                \\\"scrollable\\\".equals(field)?!n.scrollable:n.scrollable,\\\"enabled\\\".equals(field)?!n.enabled:n.enabled,\\n                \\\"password\\\".equals(field)?!n.password:n.password,child,\\n                \\\"signature\\\".equals(field)?repeat(\\\"e\\\",64):n.observedAppTreeSignature);\\n    }\\n    @SuppressWarnings(\\\"unchecked\\\")\\n    private static void terminalLifecycleCases(WebTaskDomain linked,WebTaskDomain unverified)throws Exception{\\n        test(\\\"terminal_verified_snapshot_survives_only_normal_known_close\\\",()->{\\n            TerminalFixture f=closedFixture(linked);\\n            check(!f.gate.verified(f.frame),\\\"ordinary clear still removes live completion/action eligibility\\\");\\n            rejects(()->f.gate.webDomainFor(f.frame));\\n            TaskCompletionGate.Check end=f.finish(\\\"\\\",f.frame);\\n            check(end.verified&&!end.retryAllowed,\\\"real TCG result snapshot plus explicit synthetic terminal facts\\\");\\n            Map<String,Object> result=(Map<String,Object>)end.evidence.get(\\\"public_web_result\\\");\\n            Map<String,Object> terminal=(Map<String,Object>)end.evidence.get(\\\"terminal_web_completion\\\");\\n            check(\\\"199.00\\\".equals(result.get(\\\"amount_decimal\\\"))&&\\\"CNY\\\".equals(result.get(\\\"currency\\\"))\\n                    &&Boolean.TRUE.equals(result.get(\\\"action_domain_retired\\\")),\\\"actual fixture result is retained read-only\\\");\\n            check(Boolean.FALSE.equals(result.get(\\\"business_verified\\\"))&&Boolean.FALSE.equals(terminal.get(\\\"grants_tool_authority\\\")),\\n                    \\\"completion snapshot grants no transaction or action capability\\\");\\n            boolean immutable=false;try{result.put(\\\"amount_decimal\\\",\\\"0\\\");}catch(UnsupportedOperationException expected){immutable=true;}\\n            check(immutable,\\\"nested result evidence is immutable\\\");\\n        });\\n        test(\\\"terminal_unclaimed_unstable_or_unverified_result_never_freezes\\\",()->{\\n            for(int mode=0;mode<3;mode++){\\n                TerminalFixture f=new TerminalFixture(mode==2?unverified:linked,mode!=0,mode!=1);\\n                f.retire();check(f.close==null&&!f.known(\\\"\\\")&&!f.finish(\\\"\\\",f.frame).verified,\\\"no snapshot from model intent or absent provider result\\\");\\n            }\\n        });\\n        test(\\\"terminal_final_frame_identity_changes_are_rejected\\\",()->{\\n            for(String field:Arrays.asList(\\\"observation\\\",\\\"package\\\",\\\"window\\\",\\\"display\\\",\\\"generation\\\",\\\"type\\\",\\\"metadata\\\",\\\"truncated\\\")){\\n                TerminalFixture f=closedFixture(linked);\\n                check(!f.finish(\\\"\\\",changedFrame(f.frame,field,f.frame.nodes)).verified,\\\"changed final frame: \\\"+field);\\n            }\\n            TerminalFixture absent=closedFixture(linked);check(!absent.finish(\\\"\\\",null).verified,\\\"missing final frame\\\");\\n        });\\n        test(\\\"terminal_final_native_node_changes_are_rejected\\\",()->{\\n            for(String field:Arrays.asList(\\\"id\\\",\\\"package\\\",\\\"text\\\",\\\"label\\\",\\\"view\\\",\\\"input\\\",\\\"left\\\",\\\"top\\\",\\\"right\\\",\\\"bottom\\\",\\n                    \\\"editable\\\",\\\"clickable\\\",\\\"scrollable\\\",\\\"enabled\\\",\\\"password\\\",\\\"signature\\\",\\\"child\\\",\\\"visited\\\")){\\n                TerminalFixture f=closedFixture(linked);List<NotesCompletionEvidence.Node> nodes=new ArrayList<NotesCompletionEvidence.Node>(f.frame.nodes);\\n                nodes.set(0,changedNode(nodes.get(0),field));\\n                check(!f.finish(\\\"\\\",changedFrame(f.frame,\\\"\\\",nodes)).verified,\\\"changed final node: \\\"+field);\\n            }\\n            TerminalFixture order=closedFixture(linked);List<NotesCompletionEvidence.Node> reversed=new ArrayList<NotesCompletionEvidence.Node>(order.frame.nodes);\\n            Collections.reverse(reversed);check(!order.finish(\\\"\\\",changedFrame(order.frame,\\\"\\\",reversed)).verified,\\\"native node order bound\\\");\\n            TerminalFixture count=closedFixture(linked);List<NotesCompletionEvidence.Node> shorter=new ArrayList<NotesCompletionEvidence.Node>(count.frame.nodes);\\n            shorter.remove(shorter.size()-1);check(!count.finish(\\\"\\\",changedFrame(count.frame,\\\"\\\",shorter)).verified,\\\"native node count bound\\\");\\n        });\\n        test(\\\"terminal_closed_callback_identity_is_exact\\\",()->{\\n            for(String fault:Arrays.asList(\\\"task\\\",\\\"binding\\\",\\\"status\\\",\\\"instance\\\",\\\"epoch\\\",\\\"display\\\",\\\"window\\\",\\\"callback_sha\\\")){\\n                TerminalFixture f=new TerminalFixture(linked,true,true);f.retire();\\n                check(!f.known(fault)&&!f.finish(\\\"\\\",f.frame).verified,\\\"ordinary CLOSE mismatch: \\\"+fault);\\n            }\\n            TerminalFixture nonnormal=new TerminalFixture(linked,true,true);\\n            nonnormal.close=nonnormal.gate.beginWebClose(nonnormal.lease,linked,TASK,nonnormal.binding,\\\"error\\\");\\n            nonnormal.gate.clearWebDomain();check(nonnormal.close==null&&!nonnormal.known(\\\"\\\")&&!nonnormal.finish(\\\"\\\",nonnormal.frame).verified,\\\"error close is not a normal terminal\\\");\\n        });\\n        test(\\\"terminal_unknown_abort_and_late_close_never_recover_success\\\",()->{\\n            TerminalFixture failed=new TerminalFixture(linked,true,true);failed.retire();failed.gate.abortWebClose(failed.close);\\n            check(!failed.known(\\\"\\\")&&!failed.finish(\\\"\\\",failed.frame).verified,\\\"a late positive callback cannot undo unknown close\\\");\\n            TerminalFixture noAttach=new TerminalFixture(linked,true,true);noAttach.retire();noAttach.gate.abortWebClose(noAttach.close);\\n            check(!noAttach.finish(\\\"\\\",noAttach.frame).verified,\\\"no-attach retirement is not an observed result close\\\");\\n            TerminalFixture duplicate=new TerminalFixture(linked,true,true);duplicate.retire();\\n            check(duplicate.gate.beginWebClose(duplicate.lease,linked,TASK,duplicate.binding,\\\"normal\\\")==null\\n                    &&!duplicate.known(\\\"\\\")&&!duplicate.finish(\\\"\\\",duplicate.frame).verified,\\\"one close attempt per gate\\\");\\n        });\\n        test(\\\"terminal_clear_rebind_and_late_observation_invalidate_proof\\\",()->{\\n            TerminalFixture cleared=new TerminalFixture(linked,true,true);cleared.gate.clearWebDomain();cleared.retire();\\n            check(cleared.close==null&&!cleared.finish(\\\"\\\",cleared.frame).verified,\\\"clear without prepared close cannot restore a candidate\\\");\\n            TerminalFixture rebound=new TerminalFixture(linked,true,true);rebound.gate.bindWebDomain(linked);rebound.retire();\\n            check(rebound.close==null&&!rebound.finish(\\\"\\\",rebound.frame).verified,\\\"even equal domain rebinding consumes the old claim\\\");\\n            TerminalFixture observed=new TerminalFixture(linked,true,true);\\n            observed.gate.observed(changedFrame(observed.frame,\\\"observation\\\",observed.frame.nodes));observed.gate.observed(observed.frame);observed.retire();\\n            check(observed.close==null&&!observed.finish(\\\"\\\",observed.frame).verified,\\\"return to the old frame cannot revive a changed observation\\\");\\n            TerminalFixture twice=new TerminalFixture(linked,true,true);twice.retire();twice.gate.clearWebDomain();\\n            check(!twice.known(\\\"\\\")&&!twice.finish(\\\"\\\",twice.frame).verified,\\\"exactly the prepared clear is allowed\\\");\\n            TerminalFixture late=closedFixture(linked);late.gate.observed(late.frame);\\n            check(!late.finish(\\\"\\\",late.frame).verified,\\\"late observations after retirement do not mint a proof\\\");\\n            TerminalFixture bindAfter=closedFixture(linked);rejects(()->bindAfter.gate.bindWebDomain(linked));\\n            check(!bindAfter.finish(\\\"\\\",bindAfter.frame).verified,\\\"retired action domain cannot be rebound\\\");\\n        });\\n        test(\\\"terminal_requires_actual_owner_scope_cleanup_and_native_parent_facts\\\",()->{\\n            for(String fault:Arrays.asList(\\\"lease\\\",\\\"owner\\\",\\\"owner_task\\\",\\\"no_owner\\\",\\\"step\\\",\\\"model_run\\\",\\\"model_success\\\",\\\"cleanup\\\",\\n                    \\\"helper\\\",\\\"background\\\",\\\"scope\\\",\\\"cancelled\\\",\\\"not_started\\\",\\\"not_exited\\\",\\\"exit\\\",\\\"receipt\\\",\\\"worker_task\\\",\\\"worker_generation\\\",\\\"worker_sha\\\")){\\n                TerminalFixture f=closedFixture(linked);\\n                check(!f.finish(fault,f.frame).verified,\\\"missing actual terminal fact: \\\"+fault);\\n            }\\n            TerminalFixture invalid=closedFixture(linked);invalid.gate.invalidateInstalled(\\\"synthetic post-close identity invalidation\\\");\\n            check(!invalid.finish(\\\"\\\",invalid.frame).verified,\\\"identity invalidation after a known close still wins\\\");\\n        });\\n        test(\\\"terminal_tokens_are_gate_local_and_consumed_once\\\",()->{\\n            TerminalFixture first=new TerminalFixture(linked,true,true),other=new TerminalFixture(linked,true,true);first.retire();other.retire();\\n            check(!other.gate.webCloseKnown(first.close,first.lease,TASK,first.binding,\\\"closed\\\",linked.instance,linked.epoch,7,19,repeat(\\\"a\\\",64)),\\n                    \\\"a private token cannot cross even otherwise identical gates\\\");\\n            check(!other.finish(\\\"\\\",other.frame).verified&&!first.known(\\\"\\\"),\\\"foreign/replayed token cannot produce either success\\\");\\n            TerminalFixture consumed=closedFixture(linked);\\n            check(consumed.finish(\\\"\\\",consumed.frame).verified&&!consumed.finish(\\\"\\\",consumed.frame).verified,\\\"one terminal consumption\\\");\\n        });\\n        test(\\\"terminal_flight_without_results_provider_stays_unverified\\\",()->{\\n            TaskAuthorization a=TaskAuthorization.parse(FLIGHT);TaskCompletionGate gate=new TaskCompletionGate(TASK,FLIGHT,a);\\n            WebTaskDomain pending=waiting(binding(FLIGHT));NotesCompletionEvidence.Frame f=completionFrame(pending.observationId,pending.windowId);\\n            gate.observed(f);gate.bindWebDomain(pending);check(!gate.successClaim(1,RUN,f,true).verified,\\\"no Flight provider manufactured\\\");\\n            Object lease=new Object();TaskCompletionGate.WebCloseAttempt close=gate.beginWebClose(lease,pending,TASK,(String)pending.evidence().get(\\\"binding_sha256\\\"),\\\"normal\\\");\\n            gate.clearWebDomain();check(close==null,\\\"no immutable result for the actual form/query-only provider\\\");\\n            check(!gate.terminalWebCheck(lease,f,a.bind(TASK).frame(),1,RUN,true,true,true,true,true,false,true,true,0,true,TASK,repeat(\\\"b\\\",32),repeat(\\\"c\\\",64)).verified,\\n                    \\\"synthetic positive cleanup cannot turn absent Flight data into completion\\\");\\n        });\\n    }\\n\\n    public static void main(String[] argv)throws Exception{\\n\",\"why\":\"Append direct real-TCG lifecycle tests with explicitly synthetic close/worker facts.\",\"intermediate_before\":{\"bytes\":35210,\"sha256\":\"a1dab97ae5a81eb3d5133068f66ff2057b7d4ad6afc1deff895406af9a7b82b2\",\"git_blob_sha\":\"3731b53306137dcb9b2b2f0acea31fa07fa9f25f\"},\"intermediate_after\":{\"bytes\":51068,\"sha256\":\"357c844ae653a7e157c58369882eff9125ec5c974676ba9f292e8361d481ecb3\",\"git_blob_sha\":\"eed427746e93b8d3228d21371f3660a182d8d454\"},\"count\":1},{\"before\":\"        JSONObject report=new JSONObject().put(\\\"schema\\\",\\\"hepta.v55-web-task-composition-host.v1\\\").put(\\\"all_pass\\\",true)\",\"after\":\"        terminalLifecycleCases(linked,after);\\n        WebFlightNativeStabilityHostCases.run((name,count)->{cases.add(name);assertions+=count;});\\n        JSONObject report=new JSONObject().put(\\\"schema\\\",\\\"hepta.v55-web-task-composition-host.v1\\\").put(\\\"all_pass\\\",true)\",\"why\":\"Reuse this existing suite and its original case order; append lifecycle and Mobile stability cases.\",\"intermediate_before\":{\"bytes\":51068,\"sha256\":\"357c844ae653a7e157c58369882eff9125ec5c974676ba9f292e8361d481ecb3\",\"git_blob_sha\":\"eed427746e93b8d3228d21371f3660a182d8d454\"},\"intermediate_after\":{\"bytes\":51213,\"sha256\":\"234f2dc6c48757c81c183bb6b9d17074a7d9ef3b91931fb6ddb3eb2fc12c86b4\",\"git_blob_sha\":\"d13503b4c3e4441081fa629b4e6ae6ad81164c99\"},\"count\":1},{\"before\":\"                .put(\\\"prior_case_count\\\",43).put(\\\"legacy_dom_id_bridge_assertions_replaced\\\",2)\",\"after\":\"                .put(\\\"prior_case_count\\\",43).put(\\\"legacy_dom_id_bridge_assertions_replaced\\\",2)\\n                .put(\\\"terminal_lifecycle_cases_added\\\",10).put(\\\"terminal_lifecycle_close_and_worker_inputs_synthetic\\\",true)\\n                .put(\\\"flight_native_stability_replay\\\",WebFlightNativeStabilityHostCases.provenance())\",\"why\":\"Explicitly distinguish source-derived terminal logic tests from actual Binder/native-worker proof.\",\"intermediate_before\":{\"bytes\":51213,\"sha256\":\"234f2dc6c48757c81c183bb6b9d17074a7d9ef3b91931fb6ddb3eb2fc12c86b4\",\"git_blob_sha\":\"d13503b4c3e4441081fa629b4e6ae6ad81164c99\"},\"intermediate_after\":{\"bytes\":51438,\"sha256\":\"a6cbef2e5a4be11aa38a8e5b20f49f65e6b1deaef51fe20ba3153ae0e49c54a1\",\"git_blob_sha\":\"c27618f05e5d6aaf0af5f38ac7f8dbb261366d5a\"},\"count\":1},{\"before\":\"            check(immutable,\\\"nested result evidence is immutable\\\");\\n\",\"after\":\"            check(immutable,\\\"nested result evidence is immutable\\\");\\n            Map<String,Object> page=(Map<String,Object>)end.evidence.get(\\\"official_page\\\");\\n            Map<String,Object> frozenGeometry=(Map<String,Object>)page.get(\\\"native_geometry\\\");\\n            Map<String,Object> actualGeometry=(Map<String,Object>)linked.evidence().get(\\\"native_geometry\\\");\\n            check(frozenGeometry.equals(actualGeometry)&&frozenGeometry!=actualGeometry\\n                    &&frozenGeometry.get(\\\"native_bounds_screen_pixels\\\") instanceof List,\\n                    \\\"actual provider geometry is a typed structural map with detached arrays\\\");\\n            List<Object> frozenBounds=(List<Object>)frozenGeometry.get(\\\"native_bounds_screen_pixels\\\");\\n            boolean nestedImmutable=false;\\n            try{frozenBounds.set(0,Integer.valueOf(-1));}catch(UnsupportedOperationException expected){nestedImmutable=true;}\\n            check(nestedImmutable,\\\"native geometry array is deeply immutable\\\");\\n            Object originalGeometrySha=actualGeometry.get(\\\"native_geometry_sha256\\\");\\n            try{\\n                actualGeometry.put(\\\"native_geometry_sha256\\\",repeat(\\\"e\\\",64));\\n                check(originalGeometrySha.equals(frozenGeometry.get(\\\"native_geometry_sha256\\\")),\\n                        \\\"mutating the retired provider map cannot change its terminal snapshot\\\");\\n            }finally{actualGeometry.put(\\\"native_geometry_sha256\\\",originalGeometrySha);}\\n            TerminalFixture changedBeforeClose=new TerminalFixture(linked,true,true);\\n            try{\\n                actualGeometry.put(\\\"native_geometry_sha256\\\",repeat(\\\"e\\\",64));\\n                changedBeforeClose.retire();\\n                check(changedBeforeClose.close==null&&!changedBeforeClose.known(\\\"\\\")\\n                        &&!changedBeforeClose.finish(\\\"\\\",changedBeforeClose.frame).verified,\\n                        \\\"provider geometry mutation after claim and before close rejects completion\\\");\\n            }finally{actualGeometry.put(\\\"native_geometry_sha256\\\",originalGeometrySha);}\\n\",\"count\":1}],\"proof_before\":{\"original_case_count\":43,\"successor_case_count_expected\":43,\"production_changed\":false,\"changes\":\"Explicit v4 positive card/native/ARM/NAV factories and two legacy ID-only ambiguity tests migrated to current description/region ambiguity; original provenance/TCG/price/native outcome/clock negatives retained.\",\"legacy_id_case_mapping\":[{\"old\":\"duplicate_native_resource_id_blocks_even_disabled\",\"current\":\"duplicate_native_card_description_blocks_even_disabled\"},{\"old\":\"duplicate_dom_id_blocks_product_link\",\"current\":\"ambiguous_observed_region_blocks_product_link\"}],\"peer_assertion\":\"5/v3 to current 6/v4\",\"old_source_fully_reversible\":true,\"assertion_blocks_not_claimed_wholly_byte_identical\":true},\"proof_after\":{\"original_case_count\":43,\"successor_case_count_expected\":43,\"production_changed\":false,\"changes\":\"Explicit v4 positive card/native/ARM/NAV factories and two legacy ID-only ambiguity tests migrated to current description/region ambiguity; original provenance/TCG/price/native outcome/clock negatives retained.\",\"legacy_id_case_mapping\":[{\"old\":\"duplicate_native_resource_id_blocks_even_disabled\",\"current\":\"duplicate_native_card_description_blocks_even_disabled\"},{\"old\":\"duplicate_dom_id_blocks_product_link\",\"current\":\"ambiguous_observed_region_blocks_product_link\"}],\"peer_assertion\":\"5/v3 to current 6/v4\",\"old_source_fully_reversible\":true,\"assertion_blocks_not_claimed_wholly_byte_identical\":true,\"unchanged_actual55_43_case_order_and_assertions\":true,\"appended_terminal_lifecycle_cases\":10,\"appended_native_stability_cases\":17,\"geometry_structural_map_freeze_assertions_added\":4}},\"changed_production_inputs\":[{\"before\":{\"path\":\"src/org/trillionnium/hepta/local/TaskCompletionGate.java\",\"bytes\":32946,\"sha256\":\"cce85ab866bbb2d5bb287594152513b8ee178dae9107a3b490975f0a229857d8\",\"git_blob_sha\":\"d8a894c9bd3ece4a7dca922cb5fda8a84447c789\",\"mode\":\"100644\"},\"after\":{\"path\":\"src/org/trillionnium/hepta/local/TaskCompletionGate.java\",\"bytes\":49971,\"sha256\":\"ad417d98fbd7b12bf4373270a1206c11984682c9f35b7b4a5179bb9fbff7ba98\",\"git_blob_sha\":\"48323262aaf10962f0a481cafc18c56bc82e936b\",\"mode\":\"100644\"}},{\"before\":{\"path\":\"src/org/trillionnium/hepta/local/WebShoppingDomain.java\",\"bytes\":31708,\"sha256\":\"c1c564118915d230d2b5c9ff275c05263b9253e3c876d03db7b63a5a76248aa0\",\"git_blob_sha\":\"da3880029d43376cd271df68517675615c2800bd\",\"mode\":\"100644\"},\"after\":{\"path\":\"src/org/trillionnium/hepta/local/WebShoppingDomain.java\",\"bytes\":31717,\"sha256\":\"bbf256e37eb5cc3a1619371e9c29dc5f7af3139eeb4f602f602cf0f05551bf92\",\"git_blob_sha\":\"78c1c4d616a815dbf31b214f0fb74754745c967c\",\"mode\":\"100644\"}}],\"new_production_input\":{\"path\":\"src/org/trillionnium/hepta/local/WebFlightNativeStability.java\",\"bytes\":23349,\"sha256\":\"503078f251696fb542912e5270efca13439ebcece4db8b3473e7fcb543b4fc2d\",\"git_blob_sha\":\"5d41e41c7e6c447f4dba598a12f21673c168603b\",\"mode\":\"100644\"},\"new_helper\":{\"path\":\"tests/web-flight/WebFlightNativeStabilityHostCases.java\",\"bytes\":53708,\"sha256\":\"c787261dd3953bb933560cd19b7ccc6fa0c34c56c122cf018664ce9b12afc2ca\",\"git_blob_sha\":\"71c9626ef7ddeafdc4fbd6dd7bc12fc9b1dee443\",\"raw_utf8\":\"package org.trillionnium.hepta.local;\\n\\nimport org.json.JSONArray;\\nimport org.json.JSONObject;\\nimport java.io.ByteArrayInputStream;\\nimport java.io.ByteArrayOutputStream;\\nimport java.nio.charset.StandardCharsets;\\nimport java.security.MessageDigest;\\nimport java.util.ArrayList;\\nimport java.util.Arrays;\\nimport java.util.Base64;\\nimport java.util.LinkedHashMap;\\nimport java.util.List;\\nimport java.util.Map;\\nimport java.util.zip.GZIPInputStream;\\n\\n/** Additional cases inside the existing composition run, not a new suite.\\n * Actual DOM/retained AX originals are pinned below. Full traversal snapshots\\n * are explicitly synthetic; they cannot establish a phone dispatch or visibility. */\\nfinal class WebFlightNativeStabilityHostCases {\\n    interface Sink {void passed(String name,int assertions)throws Exception;}\\n    private interface Work {void run()throws Exception;}\\n    private static int assertions;\\n    private static final String TARGET=\\\"0/2/0/7/1/0\\\",SLIDER=\\\"0/2/0/6/0\\\";\\n    private static final String[] INPUT_B64={\\\"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\\\"};\\n    private static final String INPUT_SHA=\\\"3442510142df13a488198185c77b27486c2a0337af287902675fee8204061da2\\\";\\n    private WebFlightNativeStabilityHostCases(){}\\n    private static void check(boolean value,String reason){assertions++;if(!value)throw new AssertionError(reason);}\\n    private static void reject(Work work)throws Exception{\\n        boolean rejected=false;try{work.run();}catch(IllegalArgumentException|org.json.JSONException expected){rejected=true;}\\n        check(rejected,\\\"expected bounded production predicate rejection\\\");\\n    }\\n    private static void test(Sink sink,String name,Work work)throws Exception{\\n        int old=assertions;work.run();sink.passed(name,assertions-old);\\n    }\\n    private static JSONObject copy(JSONObject value)throws Exception{return new JSONObject(value.toString());}\\n    private static JSONArray copy(JSONArray value)throws Exception{return new JSONArray(value.toString());}\\n    private static String hash(byte[] bytes)throws Exception{\\n        StringBuilder s=new StringBuilder();for(byte b:MessageDigest.getInstance(\\\"SHA-256\\\").digest(bytes))\\n            s.append(String.format(java.util.Locale.ROOT,\\\"%02x\\\",b&255));return s.toString();\\n    }\\n    private static JSONObject input()throws Exception{\\n        StringBuilder text=new StringBuilder();for(String part:INPUT_B64)text.append(part);\\n        byte[] compressed=Base64.getDecoder().decode(text.toString());ByteArrayOutputStream out=new ByteArrayOutputStream();\\n        try(GZIPInputStream stream=new GZIPInputStream(new ByteArrayInputStream(compressed))){\\n            byte[] buffer=new byte[4096];int n;while((n=stream.read(buffer))!=-1){\\n                if(out.size()+n>342642)throw new AssertionError(\\\"bounded pinned replay bytes\\\");out.write(buffer,0,n);\\n            }\\n        }\\n        byte[] bytes=out.toByteArray();if(bytes.length!=342642||!INPUT_SHA.equals(hash(bytes)))\\n            throw new AssertionError(\\\"complete actual replay input SHA differs\\\");\\n        JSONObject value=new JSONObject(new String(bytes,StandardCharsets.UTF_8));\\n        for(String pair:new String[]{\\\"actual_dom_a:dom_a_sha256\\\",\\\"actual_dom_b:dom_b_sha256\\\",\\n                \\\"before2_raw:before2_sha256\\\",\\\"before3_raw:before3_sha256\\\"}){\\n            String[] p=pair.split(\\\":\\\");\\n            if(!value.getString(p[1]).equals(hash(value.getString(p[0]).getBytes(StandardCharsets.UTF_8))))\\n                throw new AssertionError(\\\"actual raw source SHA differs\\\");\\n        }return value;\\n    }\\n    static JSONObject provenance()throws Exception{\\n        return new JSONObject().put(\\\"actual_input_sha256\\\",INPUT_SHA)\\n                .put(\\\"actual_77_bundle_git\\\",\\\"c7002d09283cfe166dfa76fcdee0f98c1bb0d584\\\")\\n                .put(\\\"actual_dom_raws_replayed\\\",2).put(\\\"actual_retained_native_frames_replayed\\\",2)\\n                .put(\\\"complete_native_traversal_fixture\\\",\\\"explicit synthetic structure, never an actual capture\\\")\\n                .put(\\\"rejected_transient_validate_graph_observed\\\",false)\\n                .put(\\\"android_node_ref_or_window_api_executed\\\",false)\\n                .put(\\\"phone_dispatch_or_business_verified\\\",false);\\n    }\\n    static void run(Sink sink)throws Exception{\\n        JSONObject actual=input();\\n        final JSONObject a=new JSONObject(actual.getString(\\\"actual_dom_a\\\")),b=new JSONObject(actual.getString(\\\"actual_dom_b\\\"));\\n        final JSONArray oldRows=new JSONObject(actual.getString(\\\"before2_raw\\\")).getJSONArray(\\\"nodes\\\");\\n        final JSONArray newRows=new JSONObject(actual.getString(\\\"before3_raw\\\")).getJSONArray(\\\"nodes\\\");\\n        test(sink,\\\"flight_home_actual_two_dom_carousel_only_difference\\\",()->{\\n            JSONObject proof=WebFlightNativeStability.compareDom(a,b);\\n            check(!proof.getBoolean(\\\"whole_dom_equal\\\"),\\\"actual whole DOM differs\\\");\\n            check(proof.getBoolean(\\\"all_other_dom_records_equal\\\"),\\\"complete non-carousel equality\\\");\\n            check(proof.getDouble(\\\"horizontal_translation_css_pixels\\\")==1200,\\\"actual horizontal translation\\\");\\n            check(proof.getJSONArray(\\\"changes\\\").length()==17,\\\"all seventeen actual changing node records retained\\\");\\n            check(!proof.getBoolean(\\\"fully_unoccluded_claimed\\\"),\\\"no paint visibility claim\\\");\\n        });\\n        test(sink,\\\"flight_home_dom_target_label_change_rejected\\\",()->{\\n            JSONObject changed=copy(b);findDom(changed,\\\"0/1/1/2/0/0/1/0/0\\\").put(\\\"aria_label\\\",\\\"changed\\\");\\n            reject(()->WebFlightNativeStability.compareDom(a,changed));\\n        });\\n        test(sink,\\\"flight_home_dom_non_carousel_geometry_rejected\\\",()->{\\n            JSONObject changed=copy(b);findDom(changed,\\\"0/1/1/2/0/0\\\").put(\\\"rect_css_pixels\\\",new JSONArray(new int[]{41,319,241,409}));\\n            reject(()->WebFlightNativeStability.compareDom(a,changed));\\n        });\\n        test(sink,\\\"flight_home_dom_extra_slider_semantics_rejected\\\",()->{\\n            JSONObject changed=copy(b);findDom(changed,\\\"0/1/1/1/0/0\\\").put(\\\"href_resolved\\\",\\\"https://m.csair.com/other\\\");\\n            reject(()->WebFlightNativeStability.compareDom(a,changed));\\n        });\\n        test(sink,\\\"flight_home_dom_vertical_or_nonuniform_motion_rejected\\\",()->{\\n            JSONObject changed=copy(b);JSONObject n=findDom(changed,\\\"0/1/1/1/0/0/0\\\");\\n            JSONArray r=n.getJSONArray(\\\"rect_css_pixels\\\");r.put(1,r.getDouble(1)+1);\\n            reject(()->WebFlightNativeStability.compareDom(a,changed));\\n            JSONObject scaled=copy(b);JSONArray s=findDom(scaled,\\\"0/1/1/1/0/1\\\").getJSONArray(\\\"rect_css_pixels\\\");\\n            s.put(2,s.getDouble(2)+1);reject(()->WebFlightNativeStability.compareDom(a,scaled));\\n        });\\n        test(sink,\\\"flight_home_dom_visible_modal_in_both_reads_rejected\\\",()->{\\n            JSONObject x=copy(a),y=copy(b);\\n            findDom(x,\\\"0/1/1/2/0/0\\\").put(\\\"aria_modal\\\",\\\"true\\\");\\n            findDom(y,\\\"0/1/1/2/0/0\\\").put(\\\"aria_modal\\\",\\\"true\\\");\\n            reject(()->WebFlightNativeStability.compareDom(x,y));\\n        });\\n        test(sink,\\\"flight_home_dom_metadata_or_membership_change_rejected\\\",()->{\\n            JSONObject changed=copy(b).put(\\\"ready_state\\\",\\\"loading\\\");\\n            reject(()->WebFlightNativeStability.compareDom(a,changed));\\n            JSONObject missing=copy(b);missing.getJSONArray(\\\"nodes\\\").remove(0);\\n            reject(()->WebFlightNativeStability.compareDom(a,missing));\\n        });\\n        test(sink,\\\"flight_home_actual_retained_native_ad_only_change\\\",()->{\\n            JSONObject proof=WebFlightNativeStability.compareRetained(oldRows,newRows,SLIDER);\\n            check(proof.getBoolean(\\\"all_non_carousel_records_equal_except_ordinal_id\\\"),\\\"actual non-ad rows retained exactly\\\");\\n            check(proof.getJSONArray(\\\"ordinal_changes\\\").length()==0,\\\"actual two frames have unchanged ordinals\\\");\\n            check(!proof.getBoolean(\\\"original_node_ref_rebound\\\"),\\\"no rebinding\\\");\\n        });\\n        test(sink,\\\"flight_home_retained_ordinal_shift_preserves_path_binding\\\",()->{\\n            JSONArray changed=copy(newRows);\\n            for(int i=0;i<changed.length();i++)changed.getJSONObject(i).put(\\\"id\\\",\\\"n\\\"+(i+100));\\n            JSONObject proof=WebFlightNativeStability.compareRetained(oldRows,changed,SLIDER);\\n            check(proof.getJSONArray(\\\"ordinal_changes\\\").length()==43,\\\"all non-ad ordinals may shift without target substitution\\\");\\n            check(!proof.getBoolean(\\\"original_node_ref_rebound\\\"),\\\"model original reference remains separately required\\\");\\n        });\\n        test(sink,\\\"flight_home_retained_target_semantics_change_rejected\\\",()->{\\n            JSONArray changed=copy(newRows);findRetained(changed,TARGET).put(\\\"text\\\",\\\"different booking control\\\");\\n            reject(()->WebFlightNativeStability.compareRetained(oldRows,changed,SLIDER));\\n        });\\n        test(sink,\\\"flight_home_synthetic_full_native_same_overlap_accepted\\\",()->{\\n            JSONObject proof=WebFlightNativeStability.compareNative(nativeFixture(false),nativeFixture(true),TARGET);\\n            check(proof.getBoolean(\\\"existing_target_overlap_unchanged\\\"),\\\"same observed coverage\\\");\\n            JSONArray overlap=proof.getJSONArray(\\\"existing_target_overlap\\\");\\n            check(overlap.length()==1&&overlap.getJSONArray(0).getInt(1)==568&&overlap.getJSONArray(0).getInt(3)==571,\\n                    \\\"the actual three-pixel edge geometry is represented, not erased\\\");\\n            check(proof.getBoolean(\\\"observed_target_interior_clear\\\"),\\\"bounded interior observation\\\");\\n            check(!proof.getBoolean(\\\"fully_unoccluded_claimed\\\"),\\\"not whole-pixel visibility\\\");\\n            check(proof.getJSONArray(\\\"changes\\\").length()==12,\\\"all explicit synthetic visibility switches recorded\\\");\\n        });\\n        test(sink,\\\"flight_home_full_native_target_change_rejected\\\",()->{\\n            JSONArray changed=nativeFixture(true);findNative(changed,TARGET).put(\\\"bounds\\\",new JSONArray(new int[]{163,568,361,706}));\\n            reject(()->WebFlightNativeStability.compareNative(nativeFixture(false),changed,TARGET));\\n        });\\n        test(sink,\\\"flight_home_full_native_ancestor_or_focus_change_rejected\\\",()->{\\n            JSONArray changed=nativeFixture(true);findNative(changed,\\\"0/2/0/7\\\").put(\\\"enabled\\\",false);\\n            reject(()->WebFlightNativeStability.compareNative(nativeFixture(false),changed,TARGET));\\n            JSONArray focused=nativeFixture(true);findNative(focused,\\\"0/2/0\\\").put(\\\"focused\\\",true);\\n            reject(()->WebFlightNativeStability.compareNative(nativeFixture(false),focused,TARGET));\\n        });\\n        test(sink,\\\"flight_home_full_native_ad_content_change_rejected\\\",()->{\\n            JSONArray changed=nativeFixture(true);findNative(changed,SLIDER+\\\"/1/0\\\").put(\\\"text\\\",\\\"changed promotion\\\");\\n            reject(()->WebFlightNativeStability.compareNative(nativeFixture(false),changed,TARGET));\\n        });\\n        test(sink,\\\"flight_home_full_native_new_overlap_rejected\\\",()->{\\n            JSONArray clear=nativeFixture(false);\\n            for(int i=0;i<clear.length();i++)if(clear.getJSONObject(i).getString(\\\"path\\\").startsWith(SLIDER+\\\"/\\\"))\\n                clear.getJSONObject(i).put(\\\"visible\\\",false);\\n            reject(()->WebFlightNativeStability.compareNative(clear,nativeFixture(true),TARGET));\\n        });\\n        test(sink,\\\"flight_home_full_native_missing_ancestor_rejected\\\",()->{\\n            JSONArray changed=nativeFixture(true);\\n            for(int i=0;i<changed.length();i++)if(\\\"0/2/0/7/1\\\".equals(changed.getJSONObject(i).getString(\\\"path\\\"))){changed.remove(i);break;}\\n            reject(()->WebFlightNativeStability.compareNative(nativeFixture(false),changed,TARGET));\\n        });\\n        test(sink,\\\"flight_home_full_native_foreign_package_or_target_path_rejected\\\",()->{\\n            JSONArray changed=nativeFixture(true);findNative(changed,TARGET).put(\\\"package\\\",\\\"foreign.app\\\");\\n            reject(()->WebFlightNativeStability.compareNative(nativeFixture(false),changed,TARGET));\\n            reject(()->WebFlightNativeStability.compareNative(nativeFixture(false),nativeFixture(true),\\\"0/2/0/6/0/1\\\"));\\n        });\\n    }\\n    private static JSONObject findDom(JSONObject value,String path)throws Exception{return findNative(value.getJSONArray(\\\"nodes\\\"),path);}\\n    private static JSONObject findNative(JSONArray values,String path)throws Exception{\\n        for(int i=0;i<values.length();i++)if(path.equals(values.getJSONObject(i).getString(\\\"path\\\")))return values.getJSONObject(i);\\n        throw new AssertionError(\\\"fixture path missing \\\"+path);\\n    }\\n    private static JSONObject findRetained(JSONArray values,String path)throws Exception{\\n        for(int i=0;i<values.length();i++)if(path.equals(values.getJSONObject(i).getJSONObject(\\\"native_tree_position\\\").getString(\\\"path\\\")))\\n            return values.getJSONObject(i);throw new AssertionError(\\\"actual retained path missing\\\");\\n    }\\n    /** Exact structure below is SYNTHETIC. Only the stated paths/visible target\\n     * and carousel rectangles were seen in the pinned before frames. */\\n    private static JSONArray nativeFixture(boolean after)throws Exception{\\n        Map<String,JSONObject> n=new LinkedHashMap<String,JSONObject>();\\n        put(n,\\\"0\\\",\\\"android.widget.FrameLayout\\\",\\\"\\\",3,new int[]{0,0,720,1280});\\n        put(n,\\\"0/0\\\",\\\"android.view.View\\\",\\\"\\\",0,new int[]{0,0,720,1280});\\n        put(n,\\\"0/1\\\",\\\"android.view.View\\\",\\\"\\\",0,new int[]{0,0,720,1280});\\n        put(n,\\\"0/2\\\",\\\"android.webkit.WebView\\\",\\\"\\\",1,new int[]{0,91,720,1280});\\n        put(n,\\\"0/2/0\\\",\\\"android.webkit.WebView\\\",\\\"\\\",8,new int[]{0,91,720,1280});\\n        for(int i=0;i<6;i++)put(n,\\\"0/2/0/\\\"+i,\\\"android.view.View\\\",\\\"\\\",0,new int[]{0,91,720,1280});\\n        put(n,\\\"0/2/0/6\\\",\\\"android.view.View\\\",\\\"\\\",1,new int[]{0,313,720,571});\\n        put(n,SLIDER,\\\"android.widget.ListView\\\",\\\"slider4\\\",8,new int[]{0,313,720,571});\\n        int[] ids={7,5,4,3,2,1,0,6};int first=after?1:4;\\n        for(int i=0;i<8;i++){\\n            int k=i-first;boolean visible=k>=0&&k<3;\\n            int[] bounds=visible?(k==0?new int[]{0,313,60,571}:k==1?new int[]{60,313,660,571}:new int[]{660,313,720,571})\\n                    :new int[]{0,0,0,0};\\n            String path=SLIDER+\\\"/\\\"+i;\\n            put(n,path,\\\"android.view.View\\\",\\\"advertising\\\"+ids[i],1,bounds).put(\\\"visible\\\",visible).put(\\\"clickable\\\",true);\\n            put(n,path+\\\"/0\\\",\\\"android.widget.Image\\\",\\\"\\\",0,bounds).put(\\\"visible\\\",visible).put(\\\"text\\\",\\\"synthetic-image-\\\"+ids[i]);\\n        }\\n        put(n,\\\"0/2/0/7\\\",\\\"android.view.View\\\",\\\"booking\\\",2,new int[]{60,568,360,706}).put(\\\"clickable\\\",true);\\n        put(n,\\\"0/2/0/7/0\\\",\\\"android.view.View\\\",\\\"\\\",0,new int[]{60,568,360,706});\\n        put(n,\\\"0/2/0/7/1\\\",\\\"android.view.View\\\",\\\"\\\",1,new int[]{162,568,360,706});\\n        put(n,TARGET,\\\"android.widget.Button\\\",\\\"\\\",0,new int[]{162,568,360,706})\\n                .put(\\\"text\\\",WebFlightNativeStability.LABEL).put(\\\"clickable\\\",true);\\n        JSONArray out=new JSONArray();for(JSONObject value:n.values())out.put(value);return out;\\n    }\\n    private static JSONObject put(Map<String,JSONObject> values,String path,String clazz,String id,int children,int[] bounds)throws Exception{\\n        String parent=path.contains(\\\"/\\\")?path.substring(0,path.lastIndexOf('/')):\\\"\\\";\\n        JSONObject value=new JSONObject().put(\\\"path\\\",path).put(\\\"parent_class\\\",parent.isEmpty()?\\\"\\\":values.get(parent).getString(\\\"class\\\"))\\n                .put(\\\"package\\\",\\\"org.trillionnium.hepta.webhelper\\\").put(\\\"window_id\\\",3593).put(\\\"class\\\",clazz).put(\\\"view_id\\\",id)\\n                .put(\\\"text\\\",\\\"\\\").put(\\\"description\\\",\\\"\\\").put(\\\"bounds\\\",new JSONArray(bounds)).put(\\\"visible\\\",true).put(\\\"enabled\\\",true)\\n                .put(\\\"clickable\\\",false).put(\\\"editable\\\",false).put(\\\"scrollable\\\",false).put(\\\"focused\\\",false).put(\\\"password\\\",false)\\n                .put(\\\"children\\\",children).put(\\\"scroll_actions\\\",\\\"explicit-synthetic-none\\\").put(\\\"ime_enter\\\",\\\"explicit-synthetic-unavailable\\\")\\n                .put(\\\"input_sha256\\\",JSONObject.NULL);\\n        values.put(path,value);return value;\\n    }\\n}\\n\",\"origin\":\"new test-only methods called by the existing Composition main; actual DOM/retained AX with explicit synthetic full-traversal extension\"},\"added_metadata\":{\"predecessor_packet\":{\"bytes\":161563,\"sha256\":\"6b2c8f192b00e95feae521e657e2bc9552b1cbf251510ef75818f5884c0cf9e3\",\"git_blob_sha\":\"7c98d42f3ea3babad09e7a47eb5121cec9a1cc7c\"},\"terminal_source_package_git\":\"2e1bf124b733b816599834c94606b2ee2dc681b8\",\"original_43_cases_and_assertions_unchanged\":true,\"added_terminal_case_names\":[\"terminal_verified_snapshot_survives_only_normal_known_close\",\"terminal_unclaimed_unstable_or_unverified_result_never_freezes\",\"terminal_final_frame_identity_changes_are_rejected\",\"terminal_final_native_node_changes_are_rejected\",\"terminal_closed_callback_identity_is_exact\",\"terminal_unknown_abort_and_late_close_never_recover_success\",\"terminal_clear_rebind_and_late_observation_invalidate_proof\",\"terminal_requires_actual_owner_scope_cleanup_and_native_parent_facts\",\"terminal_tokens_are_gate_local_and_consumed_once\",\"terminal_flight_without_results_provider_stays_unverified\"],\"added_native_stability_case_names\":[\"flight_home_actual_two_dom_carousel_only_difference\",\"flight_home_dom_target_label_change_rejected\",\"flight_home_dom_non_carousel_geometry_rejected\",\"flight_home_dom_extra_slider_semantics_rejected\",\"flight_home_dom_vertical_or_nonuniform_motion_rejected\",\"flight_home_dom_visible_modal_in_both_reads_rejected\",\"flight_home_dom_metadata_or_membership_change_rejected\",\"flight_home_actual_retained_native_ad_only_change\",\"flight_home_retained_ordinal_shift_preserves_path_binding\",\"flight_home_retained_target_semantics_change_rejected\",\"flight_home_synthetic_full_native_same_overlap_accepted\",\"flight_home_full_native_target_change_rejected\",\"flight_home_full_native_ancestor_or_focus_change_rejected\",\"flight_home_full_native_ad_content_change_rejected\",\"flight_home_full_native_new_overlap_rejected\",\"flight_home_full_native_missing_ancestor_rejected\",\"flight_home_full_native_foreign_package_or_target_path_rejected\"],\"expected_composition_cases\":70,\"expected_composition_assertions\":178,\"expected_counts_are_source_derived_not_actual_results\":true,\"actual_cases\":null,\"actual_assertions\":null,\"flight_results_provider_ready\":false,\"complete_native_traversal_fixture_synthetic\":true,\"live_binder_window_and_dispatch_executed\":false,\"native_geometry_map_fix\":\"4853e37309edf1c796775007e004fa461f72b0ac\",\"geometry_deep_freeze_assertions_added\":4}}")

def need(value, why):
    if not value:
        raise RuntimeError(why)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def blob(raw):
    return hashlib.sha1(b"blob "+str(len(raw)).encode("ascii")+b"\0"+raw).hexdigest()

def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)+"\n").encode("utf-8")

def strict(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    def no_constant(value):
        raise ValueError("non-finite JSON")
    return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs, parse_constant=no_constant)

def identity(st):
    return [st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns]

def read_regular(path, expected=None, limit=64<<20):
    path = Path(path)
    need(path.is_absolute(), "absolute input path")
    for parent in path.parents:
        st = parent.lstat()
        need(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode), "ordinary input ancestors")
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit,
         "bounded single-link ordinary input")
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        need(identity(os.fstat(fd)) == identity(before), "input replaced before open")
        chunks, size = [], 0
        while True:
            chunk = os.read(fd, min(65536, limit+1-size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            need(size <= limit, "input byte limit")
        raw = b"".join(chunks)
        need(identity(os.fstat(fd)) == identity(before), "input changed while open")
    finally:
        os.close(fd)
    need(identity(path.lstat()) == identity(before) and len(raw) == before.st_size, "input changed across read")
    facts = {"path": str(path), "bytes": len(raw), "sha256": sha(raw), "identity": identity(before)}
    if expected is not None:
        need(type(expected["bytes"]) is int and facts["bytes"] == expected["bytes"]
             and facts["sha256"] == expected["sha256"], "exact input bytes/SHA: "+str(path))
    return raw, facts

def unchanged(facts):
    raw, current = read_regular(facts["path"], facts)
    need(current == facts, "input identity changed: "+facts["path"])
    return raw

def checked(raw, pin, message):
    need(type(raw) is bytes and type(pin["bytes"]) is int and len(raw) == pin["bytes"]
         and sha(raw) == pin["sha256"], message)
    if "git_blob_sha" in pin:
        need(blob(raw) == pin["git_blob_sha"], message+" Git blob")
    return raw

def relative(name):
    need(type(name) is str and "\\" not in name and name not in ("", "."), "relative member")
    path = PurePosixPath(name)
    need(not path.is_absolute() and ".." not in path.parts and str(path) == name, "safe member")
    return name

def rows(values):
    return [{"path": name, "bytes": len(raw), "sha256": sha(raw)}
            for name, raw in sorted(values.items(), key=lambda item: Path(item[0]))]

def snapshot(root):
    need(root.is_dir() and not root.is_symlink(), "existing ordinary source root")
    values, facts = {}, {}
    for path in sorted(root.rglob("*")):
        need(not path.is_symlink(), "no source symlink")
        if path.is_dir():
            continue
        name = relative(path.relative_to(root).as_posix())
        values[name], facts[name] = read_regular(path, limit=4<<20)
    return values, facts

def validate_map(values, expected, with_git):
    need(len(expected) == len(values) and len({r["path"] for r in expected}) == len(expected),
         "exact source map membership")
    need(set(values) == {relative(r["path"]) for r in expected}, "source map path set")
    for item in expected:
        raw = values[item["path"]]
        checked(raw, item, "source map member "+item["path"])
        if with_git:
            need(blob(raw) == item["git_blob_sha"], "source map Git identity")

def write_new(path, raw, mode=0o600):
    need(ROOT in path.parents and type(raw) is bytes, "owned new output")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    for parent in path.parents:
        st = parent.lstat()
        need(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode), "ordinary output ancestors")
    fd = os.open(str(path), os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        raise
    os.chmod(path, mode)
    actual, facts = read_regular(path, {"bytes": len(raw), "sha256": sha(raw)})
    need(actual == raw, "new output readback")
    return facts

def load_bound(path, pin, original_facts):
    raw, facts = read_regular(path, pin)
    original_facts.append(facts)
    return raw


def run_step(name, argv, timeout, cwd, env):
    begin = time.monotonic()
    process, code, timed_out, forced = None, None, False, False
    group_cleanup_attempted, group_absent_observed, group_cleanup_error = False, None, None
    stdout_path, stderr_path = ROOT/(name+".stdout"), ROOT/(name+".stderr")
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        process = subprocess.Popen([str(x) for x in argv], cwd=str(cwd), env=env, stdin=subprocess.DEVNULL,
                                   stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                code = process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                forced = True
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                code = process.wait(timeout=5)
        finally:
            # A failed leader may already have exited while its compiler
            # descendants still belong to the new process group. Clean that
            # owned group on every failure, not just a still-running leader.
            if code != 0 or timed_out or process.poll() is None:
                group_cleanup_attempted = True
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                except OSError as cleanup_error:
                    group_cleanup_error = str(cleanup_error)
                if process.poll() is None:
                    try:
                        code = process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
                # The group may still exist after its leader is reaped.
                # This failure-only signal never targets another job/root.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                    forced = True
                except ProcessLookupError:
                    pass
                except OSError as cleanup_error:
                    group_cleanup_error = str(cleanup_error)
                if process.poll() is None:
                    try:
                        code = process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        group_cleanup_error = "owned leader exit not observed after bounded cleanup"
                try:
                    os.killpg(process.pid, 0)
                    group_absent_observed = False
                except ProcessLookupError:
                    group_absent_observed = True
                except OSError as cleanup_error:
                    group_absent_observed = None
                    group_cleanup_error = str(cleanup_error)
    _, stdout_facts = read_regular(stdout_path)
    _, stderr_facts = read_regular(stderr_path)
    step = {"name": name, "argv": [str(x) for x in argv], "cwd": str(cwd), "pid": process.pid,
            "exit_code": code, "timed_out": timed_out, "forced_kill": forced, "exit_observed": process.poll() is not None,
            "elapsed_seconds": time.monotonic()-begin, "stdout": stdout_facts, "stderr": stderr_facts,
            "owned_group_cleanup_attempted": group_cleanup_attempted,
            "owned_group_absent_observed_after_failure": group_absent_observed,
            "owned_group_cleanup_error": group_cleanup_error}
    steps.append(step)
    need(type(code) is int and code == 0 and not timed_out and not forced and process.poll() is not None,
         "each original Web regression process must exit normally")


def source_rows(values):
    return [{"path":name,"bytes":len(raw),"sha256":sha(raw)}
            for name,raw in sorted(values.items(),key=lambda item:Path(item[0]))]

def read_bound(path,pin):
    raw,facts=read_regular(path,pin)
    originals.append(facts)
    return raw,facts

def exact_changes(base,changes,successor):
    value=base.decode("utf-8","strict")
    for change in changes:
        need(type(change["count"]) is int and change["count"]>0
             and value.count(change["before"])==change["count"],"exact fixture predecessor occurrence")
        value=value.replace(change["before"],change["after"])
    need(value.encode("utf-8")==successor,"exact forward fixture reconstruction")
    for change in reversed(changes):
        need(value.count(change["after"])==change["count"],"exact fixture reverse occurrence")
        value=value.replace(change["after"],change["before"])
    need(value.encode("utf-8")==base,"byte-identical original fixture reverse proof")

def derive_packet(prior_raw):
    delta=PACKET_DELTA
    checked(prior_raw,delta["base"],"actual55 complete packet")
    packet=strict(prior_raw)
    need(packet["schema"]==delta["schema_before"]
         and packet["current_aggregate"]==delta["current_aggregate_before"]
         and "main56_successor" not in packet,"exact old metadata")
    composition=packet["files"][1]
    need(composition["path"]==delta["composition"]["path"]
         and composition["proof"]==delta["composition"]["proof_before"],"exact old Composition metadata")
    old_text=composition["raw_utf8"]
    checked(old_text.encode("utf-8"),delta["composition"]["before"],"actual55 Composition")
    new_text=old_text
    for change in delta["composition"]["ordered_replacements"]:
        need(change["count"]==1 and new_text.count(change["before"])==1,"one appended Composition block")
        new_text=new_text.replace(change["before"],change["after"])
    exact_changes(old_text.encode("utf-8"),delta["composition"]["ordered_replacements"],new_text.encode("utf-8"))
    checked(new_text.encode("utf-8"),delta["composition"]["after"],"reviewed terminal/stability Composition")
    composition.update(delta["composition"]["after"])
    composition["raw_utf8"]=new_text
    composition["ordered_replacements"].extend(delta["composition"]["ordered_replacements"])
    composition["proof"]=delta["composition"]["proof_after"]
    for change in delta["changed_production_inputs"]:
        matches=[i for i,row in enumerate(packet["production_inputs"]) if row["path"]==change["before"]["path"]]
        need(len(matches)==1 and packet["production_inputs"][matches[0]]==change["before"],"one exact production successor row")
        packet["production_inputs"][matches[0]]=change["after"]
    need(delta["new_production_input"]["path"] not in [r["path"] for r in packet["production_inputs"]],"new pure class unique")
    packet["production_inputs"].append(delta["new_production_input"])
    need(delta["new_helper"]["path"] not in [r["path"] for r in packet["files"]],"one new test helper unique")
    packet["files"].append(delta["new_helper"])
    packet["schema"]=delta["schema_after"]
    packet["current_aggregate"]=delta["current_aggregate_after"]
    packet["main56_successor"]=delta["added_metadata"]
    raw=encoded(packet)
    checked(raw,delta["result"],"complete current packet full pin")
    # The entire old packet must reverse byte-for-byte, including its old
    # migration proofs and every untouched fixture/assertion/raw record.
    reverse=strict(raw);rc=reverse["files"][1]
    for change in reversed(delta["composition"]["ordered_replacements"]):
        need(rc["raw_utf8"].count(change["after"])==1,"unique Composition reverse block")
        rc["raw_utf8"]=rc["raw_utf8"].replace(change["after"],change["before"])
    rc.update(delta["composition"]["before"]);rc["proof"]=delta["composition"]["proof_before"]
    rc["ordered_replacements"]=rc["ordered_replacements"][:-len(delta["composition"]["ordered_replacements"])]
    need(reverse["files"].pop()==delta["new_helper"] and reverse["production_inputs"].pop()==delta["new_production_input"],
         "only explicit helper and pure class appended")
    for change in delta["changed_production_inputs"]:
        matches=[i for i,row in enumerate(reverse["production_inputs"]) if row["path"]==change["after"]["path"]]
        need(len(matches)==1 and reverse["production_inputs"][matches[0]]==change["after"],"exact reverse production row")
        reverse["production_inputs"][matches[0]]=change["before"]
    reverse["schema"]=delta["schema_before"];reverse["current_aggregate"]=delta["current_aggregate_before"]
    del reverse["main56_successor"]
    need(encoded(reverse)==prior_raw,"whole original packet remains byte-identical")
    return raw,packet

def validate_report(report,spec,old_names):
    need(type(report) is dict and report["schema"]==spec["schema"] and report["all_pass"] is True
         and type(report["cases"]) is int and report["cases"]==spec["cases"]
         and type(report["assertions"]) is int and report["assertions"]==spec["assertions"],
         "all existing and explicitly appended Web cases must actually pass")
    names=report["case_names"]
    need(type(names) is list and len(names)==spec["cases"]
         and len(set(names))==spec["cases"] and all(type(n) is str for n in names),
         "unique complete actual Web case names")
    expected=old_names
    if spec["name"]=="composition43":
        expected=old_names+CONFIG["added_case_names"]
        need(report["terminal_lifecycle_cases_added"]==10
             and report["terminal_lifecycle_close_and_worker_inputs_synthetic"] is True,
             "explicit synthetic terminal facts")
        replay=report["flight_native_stability_replay"]
        need(replay["actual_77_bundle_git"]=="c7002d09283cfe166dfa76fcdee0f98c1bb0d584"
             and replay["actual_dom_raws_replayed"]==2 and replay["actual_retained_native_frames_replayed"]==2
             and replay["complete_native_traversal_fixture"]=="explicit synthetic structure, never an actual capture"
             and replay["rejected_transient_validate_graph_observed"] is False
             and replay["android_node_ref_or_window_api_executed"] is False
             and replay["phone_dispatch_or_business_verified"] is False,"honest actual-versus-synthetic stability replay")
        need(report["prior_case_count"]==43 and report["legacy_dom_id_bridge_assertions_replaced"]==2
             and report["full_native_action_service_or_binder_executed"] is False
             and report["synthetic_profile_assignment_not_actual_webview"] is True
             and report["actual_mi_dom_seen"] is False and report["actual_model_run_executed"] is False
             and report["binder_authenticated"] is False
             and type(report["phone_commands_executed"]) is int and report["phone_commands_executed"]==0
             and report["actual_shopping_or_flight_result_verified"] is False
             and report["final_native_and_cleanup_gates_verified"] is False,
             "explicit synthetic composition successor scope")
    elif spec["name"]=="evidence80":
        need(report["production_pure_classes_executed"] is True
             and report["android_rect_and_ax_fixture"] is True
             and report["binder_transport_authenticated"] is False
             and report["native_geometry_is_synthetic"] is True
             and type(report["phone_commands_executed"]) is int and report["phone_commands_executed"]==0
             and report["query_executed"] is False,"original pure receipt scope")
    elif spec["name"]=="calendar13":
        need(report["actual_fixture_dom_nodes"]==987
             and report["lease_and_native_ref_signatures_synthetic"] is True
             and report["original_dom_values_preserved"] is True
             and report["source_dom_schema"]=="hepta.fixed-top-document-dom.v2"
             and report["unit_envelope_schema"]=="hepta.fixed-top-document-dom.v4"
             and type(report["phone_actions"]) is int and report["phone_actions"]==0
             and report["binder_authenticated"] is False,"real calendar original within a synthetic v4 envelope")
    else:
        raise RuntimeError("unknown fixed regression")
    need(names==expected,"actual55 case order retained with only the explicit Composition cases appended")
    need(report["business_verified"] is False,"host cases cannot assert real business completion")

stage_raw=globals().get("__stage_source__")
need(type(stage_raw) is bytes and len(stage_raw)>0,"exact loader-verified source bytes")
ROOT=Path(CONFIG["root"])
SOURCE=Path(CONFIG["source_root"])
MATERIALIZED=Path(CONFIG["materialized_root"])
need(sys.platform=="linux" and ROOT.is_absolute() and SOURCE==MATERIALIZED/"source"
     and not ROOT.exists() and not ROOT.is_symlink()
     and ROOT not in MATERIALIZED.parents and MATERIALIZED not in ROOT.parents,
     "independent new Pocket4 output root")
originals=[]
# Preserve the actual successful55 output, its reports and historical failure
# copies; derive the new packet from that fixed original without overwriting it.
PRIOR=Path(CONFIG["prior_web"]["root"])
need(PRIOR.is_absolute() and ROOT!=PRIOR and ROOT not in PRIOR.parents
     and PRIOR not in ROOT.parents,"independent prior Web output")
prior_output,prior_output_facts=snapshot(PRIOR)
originals.extend(prior_output_facts.values())
prior_result_raw=checked(prior_output["RESULT.json"],CONFIG["prior_web"]["result"],"actual55 Web result")
prior_result=strict(prior_result_raw)
checked(prior_output["stage.py"],CONFIG["prior_web"]["stage"],"actual55 coordinator")
need(prior_result["schema"]=="hepta.main55-existing-web-regressions-host-stage.v1"
     and prior_result["all_pass"] is True and type(prior_result["exit_code"]) is int and prior_result["exit_code"]==0
     and prior_result["root"]==str(PRIOR)
     and prior_result["stage_sha256"]==CONFIG["prior_web"]["stage"]["sha256"]
     and all(prior_result[k] is True for k in ("originals_unchanged","written_files_unchanged","source_unchanged","prior_failed_output_preserved")),
     "complete actual55 Web and retained failure provenance")
need([x["name"] for x in prior_result["steps"]]==["compile","evidence80","composition43","calendar13"]
     and all(type(x["exit_code"]) is int and x["exit_code"]==0 and x["timed_out"] is False
             and x["forced_kill"] is False and x["exit_observed"] is True for x in prior_result["steps"]),
     "four actual prior normal processes")
for step in prior_result["steps"]:
    for stream in ("stdout","stderr"):
        name=step["name"]+"."+stream
        need(step[stream]["path"]==str(PRIOR/name),"prior stream is exact owned file")
        checked(prior_output[name],step[stream],"prior actual stream")
# Preserve the actual56 first run without treating its completed evidence80
# subreport as a complete pass. The new root never overwrites any failed output.
FAILED=Path(CONFIG["prior_failed56"]["root"])
need(FAILED.is_absolute() and FAILED not in (ROOT,PRIOR,MATERIALIZED)
     and ROOT not in FAILED.parents and FAILED not in ROOT.parents,"independent actual56 failed output")
failed_output,failed_output_facts=snapshot(FAILED)
originals.extend(failed_output_facts.values())
failed_raw=checked(failed_output["RESULT.json"],CONFIG["prior_failed56"]["result"],"actual56 failed complete result")
failed=strict(failed_raw)
checked(failed_output["stage.py"],CONFIG["prior_failed56"]["stage"],"actual56 failed coordinator")
checked(failed_output["FIXTURE-PACKET.json"],CONFIG["prior_failed56"]["packet"],"actual56 failed packet")
need(failed["schema"]=="hepta.main56-existing-web-regressions-host-stage.v1"
     and failed["all_pass"] is False and type(failed["exit_code"]) is int and failed["exit_code"]==1
     and failed["root"]==str(FAILED)
     and failed["stage_sha256"]==CONFIG["prior_failed56"]["stage"]["sha256"]
     and failed["source_candidate_git"]==CONFIG["prior_failed56"]["aggregate"]["git"]
     and all(failed[k] is True for k in ("originals_unchanged","written_files_unchanged","source_unchanged","prior_output_preserved")),
     "actual failed run and all prior preservation facts remain failures")
need([s["name"] for s in failed["steps"]]==["compile","evidence80","composition43"]
     and [s["exit_code"] for s in failed["steps"]]==[0,0,1]
     and all(type(s["exit_code"]) is int and s["timed_out"] is False and s["forced_kill"] is False
             and s["exit_observed"] is True for s in failed["steps"]),"original compile/pass/failure process sequence")
for step in failed["steps"]:
    for stream in ("stdout","stderr"):
        leaf=step["name"]+"."+stream
        need(step[stream]["path"]==str(FAILED/leaf),"failed-run log remains in its original root")
        checked(failed_output[leaf],step[stream],"original failed-run log")
checked(failed_output["composition43.stderr"],CONFIG["prior_failed56"]["composition_stderr"],"original geometry freeze exception")
need(set(failed["reports"])=={"evidence80"} and failed["reports"]["evidence80"]["report"]["all_pass"] is True
     and failed["reports"]["evidence80"]["report"]["cases"]==80
     and failed["reports"]["evidence80"]["report"]["assertions"]==92,"only original evidence80 subgate passed")
prior_packet_raw=checked(prior_output["FIXTURE-PACKET.json"],CONFIG["prior_web"]["packet"],"actual55 packet")
packet_raw,packet=derive_packet(prior_packet_raw)
checked(packet_raw,CONFIG["decoded_input"],"explicit56 complete fixture packet")
need(packet["schema"]=="hepta.main56-web-regression-fixture-successor.v1"
     and packet["status"]=="source_only_not_executed","reviewed fixture successor packet")
aggregate_raw,_=read_bound(MATERIALIZED/"AGGREGATE.json",CONFIG["aggregate"])
need(blob(aggregate_raw)==CONFIG["aggregate"]["git"],"complete current595 aggregate Git identity")
aggregate=strict(aggregate_raw)
inventory_raw,_=read_bound(MATERIALIZED/"SOURCE-INVENTORY.json",CONFIG["inventory"])
before,before_facts=snapshot(SOURCE)
need(len(before)==CONFIG["source_file_count"]==595 and len(aggregate["inventory"]["files"])==595,"complete current source tree")
validate_map(before,aggregate["inventory"]["files"],True)
need(inventory_raw==encoded(source_rows(before)),"complete current595 runtime source inventory")
need(packet["current_aggregate"]["git"]==CONFIG["aggregate"]["git"]
     and packet["current_aggregate"]["bytes"]==CONFIG["aggregate"]["bytes"]
     and packet["current_aggregate"]["sha256"]==CONFIG["aggregate"]["sha256"]
     and packet["current_aggregate"]["inventory_sha256"]==aggregate["inventory"]["sha256"],
     "fixture packet bound to the same full Git-bearing candidate map")
originals.extend(before_facts.values())
for flag in ("evidence80_original_main_byte_identical","calendar13_asserted_body_byte_identical",
             "composition43_explicit_fixture_successor","original_three_java_sources_not_overwritten",
             "gate_counts_are_separate_not_a_sum_with_core101"):
    need(packet["scope"][flag] is True,"explicit fixture migration scope")
for flag in ("compiled","host_executed","production_sources_modified","actual_Mi_detail_seen",
             "actual_popup_or_profile_callback","actual_business_verified"):
    need(packet["scope"][flag] is False,"no prior fixture execution or business claim")
need(type(packet["scope"]["phone_commands"]) is int and packet["scope"]["phone_commands"]==0,
     "source-only packet")
expected_fixture_names=[
    "tests/web-flight/WebFlightEvidenceHostTest.java",
    "tests/web-flight/WebTaskCompositionHostTest.java",
    "tests/web-flight/WebCalendarNativeHostTest.java",
    "tests/web-flight/WebV4RegressionFixtures.java",
    "tests/web-flight/WebWire4SyntheticFactory.java",
    "tests/web-flight/WebFlightNativeStabilityHostCases.java"]
need([item["path"] for item in packet["files"]]==expected_fixture_names,"fixed exact six fixture members")
fixture_bytes={}
for index,item in enumerate(packet["files"]):
    name=relative(item["path"])
    raw=checked(item["raw_utf8"].encode("utf-8","strict"),item,"exact fixture successor member")
    need(blob(raw)==item["git_blob_sha"],"fixture successor Git identity")
    if index<3:
        need(name in before,"unchanged current original Java fixture")
        checked(before[name],item["base"],"original Java predecessor")
        need(blob(before[name])==item["base"]["git_blob_sha"],"original Java Git identity")
        exact_changes(before[name],item["ordered_replacements"],raw)
    else:
        need(name not in before,"new fixtures do not shadow any current source file")
    fixture_bytes[name]=raw
need([len(item["ordered_replacements"]) for item in packet["files"][:3]]==[3,28,3],
     "only reviewed exact migration hunks")
need(packet["files"][0]["proof"]["main_byte_identical"] is True
     and packet["files"][2]["proof"]["main_asserted_body_byte_identical"] is True
     and packet["files"][1]["proof"]["assertion_blocks_not_claimed_wholly_byte_identical"] is True,
     "accurate original assertion boundaries")
production=packet["production_inputs"]
extra=packet["unchanged_extra_inputs"]
need(type(production) is list and len(production)==44
     and len({item["path"] for item in production})==44
     and all(item["path"].startswith("src/") and item["path"].endswith(".java") for item in production),
     "fixed44 actual production compilation units")
need([item["path"] for item in extra]==[
    "tests/qualification-scope/fixtures/android/graphics/Rect.java",
    "tests/web-flight/WebUnstartedRetirementHostTest.java"],"two unchanged auxiliary compilation units")
for item in production+extra:
    name=relative(item["path"])
    need(name in before,"actual compilation input exists")
    checked(before[name],item,"actual complete compilation unit")
    need(blob(before[name])==item["git_blob_sha"],"actual compilation unit Git identity")
need(extra[1]["only_initial_and_confirmation_factories_called_here"] is True
     and extra[1]["old_36_main_run_here"] is False,"old36 not represented as rerun")
java_names=[item["path"] for item in production+extra]+expected_fixture_names
need(len(java_names)==52 and len(set(java_names))==52,"complete unique52 Java closure")
calendar_specs=packet["actual_calendar_fixtures"]
need([Path(item["path"]).name for item in calendar_specs]==[
    "calendar-pending.json","calendar-stable.json","calendar-stable.xml"],
    "actual pending/stable calendar and native AX")
calendar_facts=[]
for item in calendar_specs:
    _,facts=read_bound(item["path"],item);calendar_facts.append(facts)
old_reports={}
need(set(prior_result["reports"])=={x["name"] for x in CONFIG["prior_expected_gates"]},"three prior actual reports")
for spec in CONFIG["prior_expected_gates"]:
    name=spec["name"];record=prior_result["reports"][name]
    path=PRIOR/(name+"-RESULT.json")
    need(record["original"]["path"]==str(path),"actual55 report path")
    raw=checked(prior_output[path.name],record["original"],"actual55 original report")
    report=strict(raw)
    need(report==record["report"] and report["all_pass"] is True
         and type(report["cases"]) is int and report["cases"]==spec["cases"]
         and type(report["assertions"]) is int and report["assertions"]==spec["assertions"]
         and type(report["case_names"]) is list and len(report["case_names"])==spec["cases"]
         and len(set(report["case_names"]))==spec["cases"],"actual55 baseline names and counts")
    old_reports[name]={"raw":raw,"facts":prior_output_facts[path.name],"report":report}
need(len(CONFIG["added_case_names"])==27 and len(set(CONFIG["added_case_names"]))==27
     and not set(CONFIG["added_case_names"]).intersection(old_reports["composition43"]["report"]["case_names"]),
     "only unique appended cases, old43 order and assertions retained")
tools={}
for name in ("java","javac","json"):
    _,facts=read_bound(CONFIG[name]["path"],CONFIG[name])
    tools[name]=facts
for name in ("java","javac"):
    need(os.access(tools[name]["path"],os.X_OK),"actual executable JDK")
ready_raw,_=read_bound(CONFIG["orgjson_ready"]["path"],CONFIG["orgjson_ready"])
ready=strict(ready_raw)
# The exact actual READY bytes are pinned; the JAR itself is independently read/hash checked.
need(type(ready) is dict,"actual JSON dependency READY object")
python_path=Path(sys.executable).resolve(strict=True)
_,python_facts=read_regular(python_path)
originals.append(python_facts);tools["python"]=python_facts
env=dict(os.environ)
for name in ("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","CLASSPATH","SOURCE_HEAD_SHA"):
    env.pop(name,None)
env["PYTHONDONTWRITEBYTECODE"]="1"
started=time.time()
ROOT.mkdir(mode=0o700)  # FIRST MUTATION; outside the handler, never share a previous result root.
steps,written=[],[]
reports={}
result={"schema":"hepta.main56-existing-web-regressions-host-stage.v1",
        "all_pass":False,"exit_code":1,"root":str(ROOT),"source_root":str(SOURCE),
        "source_candidate_git":CONFIG["aggregate"]["git"],"source_file_count":595,
        "source_inventory_sha256":CONFIG["inventory"]["sha256"],
        "candidate_git_bearing_inventory_sha256":aggregate["inventory"]["sha256"],
        "fixture_packet":CONFIG["decoded_input"],"fixture_count":6,
        "production_java_count":44,"compilation_unit_count":52,"steps":steps,"reports":reports,
        "prior_reports":{name:value["facts"] for name,value in old_reports.items()},
        "actual_calendar_originals":calendar_facts,"tools":tools,
        "core101_pass_prerequisite_required":False,"android_build_prerequisite_required":False,
        "evidence80_original_main_byte_identical":True,"calendar13_asserted_body_byte_identical":True,
        "composition43_explicit_fixture_successor":True,"composition_case_name_mapping":CONFIG["case_name_mapping"],
        "old_unstarted36_main_executed_here":False,"focused39_rerun":False,"identity10_rerun":False,
        "query40_rerun":False,"core101_rerun":False,
        "android_compiled":False,"binder_transport_executed":False,"native_accessibility_executed":False,
        "external_model_used":False,"phone_actions":0,"business_verified":False,
        "actual_Mi_detail_or_popup_verified":False,"signed":False,"published":False,
        "started_epoch":started,"originals_unchanged":False,"error":None,
        "prior_successful_web_result":dict(CONFIG["prior_web"]["result"],path=str(PRIOR/"RESULT.json")),
        "prior_output_count":len(prior_output),
        "prior_output_inventory_sha256":sha(encoded(source_rows(prior_output))),
        "prior_output_preserved":False,
        "prior_failed56_web_result":dict(CONFIG["prior_failed56"]["result"],path=str(FAILED/"RESULT.json")),
        "prior_failed56_output_count":len(failed_output),
        "prior_failed56_output_inventory_sha256":sha(encoded(source_rows(failed_output))),
        "prior_failed56_output_preserved":False,
        "geometry_deep_freeze_assertions_added":4,
        "fixture_packet_derived_from_actual55":True,
        "old_fixture_packet":CONFIG["prior_web"]["packet"],
        "existing_actual55_assertions_changed_here":False,
        "added_terminal_cases":10,"added_native_stability_cases":17,
        "expected_counts_are_source_derived_until_actual_report":True,
        "changed_production_input_paths":[r["after"]["path"] for r in PACKET_DELTA["changed_production_inputs"]]+[PACKET_DELTA["new_production_input"]["path"]],
        "actual_flight_results_provider_ready":False}
class_before=None
classes=ROOT/"classes"
try:
    written.append(write_new(ROOT/"stage.py",stage_raw))
    written.append(write_new(ROOT/"CONFIG.json",encoded(CONFIG)))
    written.append(write_new(ROOT/"FIXTURE-PACKET.json",packet_raw))
    written.append(write_new(ROOT/"SOURCE-INVENTORY.json",inventory_raw))
    written.append(write_new(ROOT/"prior-success/RESULT.json",prior_result_raw))
    written.append(write_new(ROOT/"FIXTURE-DELTA.json",encoded(PACKET_DELTA)))
    written.append(write_new(ROOT/"PRIOR-OUTPUT-INVENTORY.json",encoded(source_rows(prior_output))))
    written.append(write_new(ROOT/"prior-failed56/RESULT.json",failed_raw))
    written.append(write_new(ROOT/"PRIOR-FAILED56-OUTPUT-INVENTORY.json",encoded(source_rows(failed_output))))
    written.append(write_new(ROOT/"COMPILATION-INPUTS.json",encoded([
        {"role":"actual_production" if item in production else "unchanged_fixture",**item}
        for item in production+extra]+[
        {"role":"explicit_fixture_successor","path":item["path"],"bytes":item["bytes"],
         "sha256":item["sha256"],"git_blob_sha":item["git_blob_sha"]} for item in packet["files"]])))
    for name,raw in fixture_bytes.items():
        written.append(write_new(ROOT/"fixtures"/name,raw))
    for name,value in old_reports.items():
        written.append(write_new(ROOT/"prior"/(name+".json"),value["raw"]))
    classes.mkdir(mode=0o700)
    (ROOT/"tmp").mkdir(mode=0o700);env["TMPDIR"]=str(ROOT/"tmp")
    sources=[SOURCE/item["path"] for item in production+extra]+[
        ROOT/"fixtures"/name for name in expected_fixture_names]
    compile_argv=[tools["javac"]["path"],"--release","8","-encoding","UTF-8",
                  "-Xlint:all","-Werror","-cp",tools["json"]["path"],"-d",classes]+sources
    written.append(write_new(ROOT/"START-ARGS.json",encoded({
        "key":CONFIG["key"],"compile_argv":[str(x) for x in compile_argv],
        "test_classes":[item["class_name"] for item in CONFIG["expected_gates"]],
        "synthetic_fixture_scope":packet["scope"],"source_modified":False,"phone_actions":0})))
    run_step("compile",compile_argv,120,ROOT,env)
    class_bytes,class_facts=snapshot(classes)
    need(len(class_bytes)>0 and all(name.endswith(".class") for name in class_bytes),
         "actual nonempty compiled Java class set")
    class_before=(class_bytes,class_facts)
    result["compiled_class_count"]=len(class_bytes)
    written.append(write_new(ROOT/"COMPILED-CLASSES.json",encoded(source_rows(class_bytes))))
    cp=str(classes)+os.pathsep+tools["json"]["path"]
    for spec in CONFIG["expected_gates"]:
        out=ROOT/(spec["name"]+"-RESULT.json")
        args=[tools["java"]["path"],"-cp",cp,spec["class_name"]]
        if spec["name"]=="calendar13":
            args.extend([item["path"] for item in calendar_specs])
        args.append(out)
        run_step(spec["name"],args,120,ROOT,env)
        raw,facts=read_regular(out);report=strict(raw)
        written.append(facts)
        validate_report(report,spec,old_reports[spec["name"]]["report"]["case_names"])
        reports[spec["name"]]={"original":facts,"report":report}
    need(len(steps)==4 and len(reports)==3,"compile and all three original gates completed")
    result["all_pass"]=True;result["exit_code"]=0
except BaseException as failure:
    result["all_pass"]=False;result["exit_code"]=1
    result["error"]=type(failure).__name__+": "+str(failure)
    try:write_new(ROOT/"ERROR.txt",traceback.format_exc().encode("utf-8"))
    except BaseException as logging_failure:
        result["error_record_failure"]=type(logging_failure).__name__+": "+str(logging_failure)
finally:
    # Retain any real partial output after a failed process; never synthesize a pass.
    partial={}
    for spec in CONFIG["expected_gates"]:
        path=ROOT/(spec["name"]+"-RESULT.json")
        try:
            if path.exists():
                raw,facts=read_regular(path)
                partial[spec["name"]]={"original":facts,"report":strict(raw)}
        except BaseException as partial_failure:
            result["all_pass"]=False;result["exit_code"]=1
            partial[spec["name"]]={"read_error":type(partial_failure).__name__+": "+str(partial_failure)}
    result["actual_report_files"]=partial
    try:
        for facts in originals:unchanged(facts)
        for facts in written:unchanged(facts)
        for step in steps:
            unchanged(step["stdout"]);unchanged(step["stderr"])
        after,after_facts=snapshot(SOURCE)
        need(after==before and after_facts==before_facts,"whole595 source bytes and identities unchanged")
        need(snapshot(PRIOR)==(prior_output,prior_output_facts),
             "all prior Web output bytes and identities unchanged")
        result["prior_output_preserved"]=True
        need(snapshot(FAILED)==(failed_output,failed_output_facts),
             "all actual56 failed output bytes and identities unchanged")
        result["prior_failed56_output_preserved"]=True
        if class_before is not None:
            class_after=snapshot(classes)
            need(class_after==class_before,"compiled class bytes and identities unchanged across all gates")
        result["originals_unchanged"]=True
        result["written_files_unchanged"]=True
        result["source_unchanged"]=True
    except BaseException as integrity_failure:
        result["all_pass"]=False;result["exit_code"]=1
        result["integrity_error"]=type(integrity_failure).__name__+": "+str(integrity_failure)
    result["finished_epoch"]=time.time()
    result["elapsed_seconds"]=result["finished_epoch"]-started
    result["stage_sha256"]=sha(stage_raw)
    result["original_guard_count"]=len(originals)
    result["written_guard_count"]=len(written)
    result["all_pass"]=bool(result["all_pass"] and result["originals_unchanged"])
    result["exit_code"]=0 if result["all_pass"] else 1
    result_facts=write_new(ROOT/"RESULT.json",encoded(result))
    summary={"schema":"hepta.main56-existing-web-regressions-host-summary.v1",
        "all_pass":result["all_pass"],"exit_code":result["exit_code"],"result":result_facts,
        "error":result.get("error"),"source_file_count":595,
        "source_inventory_sha256":CONFIG["inventory"]["sha256"],
        "reports":{name:{"cases":value["report"]["cases"],"assertions":value["report"]["assertions"],
                         "all_pass":value["report"]["all_pass"]} for name,value in reports.items()},
        "android_compiled":False,"phone_actions":0,"business_verified":False,
        "core101_rerun":False,"query40_rerun":False,"focused39_rerun":False}
    write_new(ROOT/"SUMMARY.json",encoded(summary))
    print(json.dumps(summary,sort_keys=True,ensure_ascii=False,allow_nan=False),flush=True)
raise SystemExit(result["exit_code"])
