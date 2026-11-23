package org.trillionnium.hepta.background;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Looper;
import android.os.SystemClock;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.JSONArray;
import org.json.JSONObject;

/** Root-only, bounded identity catalogue. It never creates a display, user, task, or input. */
public final class ProfileCatalogueMain {
    private static final long LIMIT_MS=7000;
    private ProfileCatalogueMain(){}
    public static void main(String[] args){
        final long deadline=SystemClock.elapsedRealtime()+LIMIT_MS;
        final AtomicBoolean emitted=new AtomicBoolean();
        int exit=70;int owner=-1;String request=null;
        try{
            if(args.length!=4||!"--owner-uid".equals(args[0])||!"--request-id".equals(args[2])
                    ||!args[1].matches("[1-9][0-9]{4}")||!ProfileIdentity.uuid(args[3]))
                throw new IOException("PROFILE_CATALOGUE_ARGUMENTS");
            owner=Integer.parseInt(args[1]);request=args[3];
            if(owner<10000||owner>=90000||android.os.Process.myUid()!=0)
                throw new IOException("PROFILE_CATALOGUE_ROOT_OWNER_REQUIRED");
            final int boundOwner=owner;final String boundRequest=request;
            Thread watchdog=new Thread(()->{
                while(SystemClock.elapsedRealtime()<deadline){
                    try{Thread.sleep(Math.max(1,Math.min(100,deadline-SystemClock.elapsedRealtime())));}
                    catch(InterruptedException ignored){}
                }
                emit(emitted,boundOwner,boundRequest,null,"PROFILE_CATALOGUE_DEADLINE");
                // No display or task can exist in this read-only process.
                Runtime.getRuntime().halt(70);
            },"HeptaProfileCatalogueDeadline");
            watchdog.setDaemon(true);watchdog.start();
            if(Looper.getMainLooper()==null)Looper.prepareMainLooper();
            Object thread=Class.forName("android.app.ActivityThread").getMethod("systemMain").invoke(null);
            Context system=(Context)thread.getClass().getMethod("getSystemContext").invoke(thread);
            Context shell=system.createPackageContext("com.android.shell",0);
            String[] owners=shell.getPackageManager().getPackagesForUid(owner);
            if(owners==null||!Arrays.asList(owners).contains("org.trillionnium.hepta.local"))
                throw new IOException("PROFILE_CATALOGUE_OWNER_MISMATCH");
            ProfilePackages packages=new ProfilePackages(shell);
            List<String> targets=new ArrayList<String>();
            for(int user:packages.selectableUsers())for(String packageName:ProfileTarget.PACKAGES){
                try{targets.add(packages.read(user,packageName,true,deadline).target.wire());}
                catch(PackageManager.NameNotFoundException missing){ /* Package not installed in this profile. */ }
                catch(IOException unavailable){
                    String code=unavailable.getMessage();
                    if(!"PROFILE_NOT_RUNNING_UNLOCKED".equals(code)&&!"PROFILE_PACKAGE_UNAVAILABLE".equals(code)
                            &&!"PROFILE_USER_NOT_ELIGIBLE".equals(code))throw unavailable;
                }
            }
            if(SystemClock.elapsedRealtime()>=deadline)throw new IOException("PROFILE_CATALOGUE_DEADLINE");
            emit(emitted,owner,request,targets,null);exit=0;
        }catch(Throwable error){emit(emitted,owner,request,null,"PROFILE_CATALOGUE_UNAVAILABLE");}
        System.exit(exit);
    }
    private static void emit(AtomicBoolean emitted,int owner,String request,List<String> targets,String error){
        if(!emitted.compareAndSet(false,true))return;
        try{
            JSONObject row=new JSONObject().put("schema","hepta.profile-catalogue.v1")
                    .put("owner_uid",owner).put("request_id",request==null?JSONObject.NULL:request)
                    .put("targets",new JSONArray(targets==null?java.util.Collections.emptyList():targets));
            if(error!=null)row.put("error",error);
            System.out.println(row.toString());System.out.flush();
        }catch(Throwable ignored){System.err.println("profile_catalogue_output_failed");}
    }
}
