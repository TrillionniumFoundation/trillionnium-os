    private static java.util.Map<String,Object> nativeProfileCleanup(BackgroundSession.Cleanup cleanup){
        if(cleanup==null||!cleanup.known)return null;
        try{
            JSONObject raw=cleanup.evidence.optJSONObject("profile_cleanup");if(raw==null)return null;
            java.util.Map<String,Object> value=new java.util.LinkedHashMap<String,Object>();
            java.util.Iterator<String> keys=raw.keys();int count=0;
            while(keys.hasNext()){
                String key=keys.next();if(++count>14)return null;Object item=raw.get(key);
                if("owned_tasks".equals(key)){
                    if(!(item instanceof JSONArray))return null;JSONArray rows=(JSONArray)item;
                    if(rows.length()>32)return null;
                    java.util.List<java.util.Map<String,Object>> copied=new java.util.ArrayList<java.util.Map<String,Object>>();
                    for(int i=0;i<rows.length();i++)copied.add(completionFixed(rows.getJSONObject(i)));
                    value.put(key,copied);
                }else if(item instanceof String||item instanceof Boolean||item instanceof Integer||item instanceof Long)value.put(key,item);
                else return null;
            }
            return NativeAppEvidence.immutableMap(value);
        }catch(Exception invalid){return null;}
    }
