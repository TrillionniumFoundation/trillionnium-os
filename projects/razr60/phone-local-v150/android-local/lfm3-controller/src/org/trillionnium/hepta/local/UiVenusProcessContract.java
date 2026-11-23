package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Separate App wrapper identity. SELinux/maps qualification remains an independent actual-run check. */
public final class UiVenusProcessContract {
    private UiVenusProcessContract() {}
    public static List<String> verify(Map<String,Object> binding,Map<String,Object> core,UiVenusContract.Expected x,int exit){
        List<String> errors=new ArrayList<String>();
        UiVenusContract.check(errors,exit==0,"wrapper_process_exit");
        eq(errors,binding,"schema","hepta.ui-venus.app-process-binding.v1");
        eq(errors,binding,"worker_artifact_role","ordinary-app-model-only-candidate");eq(errors,binding,"request_id",x.id);
        for(String k:new String[]{"expected_app_uid","uid","euid"})num(errors,binding,k,x.uid);
        for(String k:new String[]{"expected_parent_pid","observed_parent_pid"})num(errors,binding,k,x.parent);
        long pid=UiVenusContract.integer(core.get("pid"));UiVenusContract.check(errors,pid>1&&pid!=x.parent,"core_child_pid");num(errors,binding,"pid",pid);
        eq(errors,binding,"parent_package","org.trillionnium.hepta.local");num(errors,binding,"parent_death_signal",9);
        for(String k:new String[]{"direct_parent_verified_before","direct_parent_verified_after","private_scope_verified_before",
                "private_scope_verified_after","same_directory_bootstrap_verified"})eq(errors,binding,k,true);
        num(errors,binding,"core_return_code",0);num(errors,binding,"wrapper_return_code",0);
        eq(errors,binding,"app_files_directory",x.files);eq(errors,binding,"run_directory",x.run);
        eq(errors,binding,"model_directory",x.files+"/"+UiVenusPins.MODEL_DIRECTORY);
        eq(errors,binding,"native_result_path",x.run+"/native-result.json");eq(errors,binding,"raw_output_path",x.run+"/raw.txt");
        eq(errors,binding,"parent_cmdline_policy","exact-package-followed-only-by-NUL-padding");
        byte[] packageName="org.trillionnium.hepta.local".getBytes(StandardCharsets.UTF_8);
        for(String when:new String[]{"before","after"}){
            long count=UiVenusContract.integer(binding.get("parent_cmdline_bytes_"+when));
            boolean size=count>packageName.length&&count<=4096;UiVenusContract.check(errors,size,"parent_cmdline_size_"+when);
            if(size){byte[] padded=new byte[(int)count];System.arraycopy(packageName,0,padded,0,packageName.length);
                eq(errors,binding,"parent_cmdline_sha256_"+when,MobiMindContract.sha(padded));}
            Object status=binding.get("parent_status_sha256_"+when);
            UiVenusContract.check(errors,status instanceof String&&((String)status).matches("[0-9a-f]{64}"),"parent_status_sha_"+when);
        }
        // /proc status changes with memory and scheduler state. Its two hashes must not be required equal.
        for(String k:new String[]{"selinux_domain_proven","ordinary_app_qualification_claimed","native_action_authorized","actions_dispatched"})eq(errors,binding,k,false);
        return errors;
    }
    private static void eq(List<String> e,Map<String,Object> v,String k,Object expected){UiVenusContract.equal(e,v,k,expected);}
    private static void num(List<String> e,Map<String,Object> v,String k,long expected){UiVenusContract.number(e,v,k,expected);}
}
