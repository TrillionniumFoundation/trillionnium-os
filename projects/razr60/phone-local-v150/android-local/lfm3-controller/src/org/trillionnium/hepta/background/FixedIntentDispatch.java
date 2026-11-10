package org.trillionnium.hepta.background;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;

/** Only two compiled local targets; no caller-supplied action, component, URI or extras. */
public final class FixedIntentDispatch {
    private FixedIntentDispatch(){}
    private static void require(boolean value,String message){if(!value)throw new IllegalStateException("fixed_intent: "+message);}
    public static FixedIntentTarget inspect(Context context,int ordinaryUid,String action)throws Exception{
        FixedIntentTools.Profile profile=FixedIntentTools.forAction(action);
        require(profile!=null&&ordinaryUid>=10000&&ordinaryUid<90000,"ordinary user-0 caller and compiled tool required");
        PackageManager pm=context.getPackageManager();ComponentName component=new ComponentName(profile.packageName,profile.className);
        ActivityInfo info=pm.getActivityInfo(component,0);
        require(info!=null&&info.applicationInfo!=null&&profile.packageName.equals(info.packageName)
                &&profile.className.equals(info.name)&&profile.packageName.equals(info.applicationInfo.packageName),"exact installed component required");
        require(info.enabled&&info.exported&&info.applicationInfo.enabled,"component unavailable to ordinary app");
        require(info.applicationInfo.uid>=10000&&info.applicationInfo.uid<90000,"target must be an ordinary installed user-0 app");
        if(info.permission!=null&&!info.permission.isEmpty())
            require(context.checkPermission(info.permission,-1,ordinaryUid)==PackageManager.PERMISSION_GRANTED,"ordinary caller lacks activity permission");
        Intent query=new Intent(profile.intentAction).setPackage(profile.packageName);
        if(profile.mimeType!=null)query.setType(profile.mimeType);
        boolean matches=false;
        for(ResolveInfo resolved:pm.queryIntentActivities(query,PackageManager.MATCH_DEFAULT_ONLY)){
            ActivityInfo found=resolved.activityInfo;
            if(found!=null&&profile.packageName.equals(found.packageName)&&profile.className.equals(found.name)
                    &&found.applicationInfo!=null&&found.applicationInfo.uid==info.applicationInfo.uid&&found.enabled&&found.exported)matches=true;
        }
        require(matches,"installed component does not declare the fixed public intent");
        return new FixedIntentTarget(action,String.valueOf(pm.getApplicationLabel(info.applicationInfo)),info.applicationInfo.uid,info.permission);
    }
    public static Intent intent(FixedIntentTarget target,String payload){
        require(target!=null,"installed target required");FixedIntentTools.Profile profile=FixedIntentTools.forAction(target.action);
        profile.validatePayload(payload);
        Intent result=new Intent(profile.intentAction).setComponent(new ComponentName(profile.packageName,profile.className));
        if(profile.mimeType!=null)result.setType(profile.mimeType);
        result.putExtra(profile.extraName,payload);
        return result.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK|Intent.FLAG_ACTIVITY_MULTIPLE_TASK);
    }
    public static void recheck(Context context,int ordinaryUid,FixedIntentTarget expected)throws Exception{
        require(expected!=null&&expected.sameIdentity(inspect(context,ordinaryUid,expected.action)),"installed target identity changed");
    }
}
