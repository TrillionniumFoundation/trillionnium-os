package org.trillionnium.hepta.background;

import java.util.List;
import org.json.JSONObject;

/** Real ProfileOwnedTask and public history producer on the existing explicit
 * Android/Binder/clock fixture. No phone, broker process or model is run. */
public final class PublicProfileBridgeProducer {
    private final Platform platform;
    private final ProfileOwnedTask owned;
    public final ProfileTarget target;
    public final String generation;
    private boolean finished;

    private static final class Platform implements ProfileOwnedTask.Platform {
        final ProfileBrokerHostTest.Fake io=new ProfileBrokerHostTest.Fake();
        String current=ForegroundConcurrencyHostTest.raw(0);
        public ProfileTarget recheck(boolean ready){return io.recheck(ready);}
        public void guard()throws Exception{io.guard();}
        public long now(){return io.now();}
        public Object newCookie(){return io.newCookie();}
        public ProfileTaskPolicy.Snapshot snapshot()throws Exception{return io.snapshot();}
        public ProfileTaskPolicy.Recents recents()throws Exception{return io.recents();}
        public String publicRecentsDump(){return io.recentsApp?ForegroundConcurrencyHostTest.withLeaf(current,200,300):current;}
        public List<BackgroundOwnedSingleTask.Task> roots(){return io.roots();}
        public List<BackgroundOwnedSingleTask.Task> children(Object token){return io.children(token);}
        public void createRoot(Object cookie){io.createRoot(cookie);}
        public void bindRoot(Object token,Object cookie){io.bindRoot(token,cookie);}
        public void removeLeaf(Object token)throws Exception{io.removeLeaf(token);}
        public boolean deleteRoot(Object token)throws Exception{return io.deleteRoot(token);}
        public void pause(){io.pause();}
    }

    public PublicProfileBridgeProducer(ProfileTarget target,String generation,long started,boolean publicHistory)throws Exception{
        this.target=target;this.generation=generation;platform=new Platform();platform.io.actual=target;platform.io.now=started;
        PublicProfileRecentHistory.Baseline history=publicHistory
                ?new PublicProfileRecentHistory.Baseline(PublicProfileRecentHistory.absence(platform.current,target),started):null;
        owned=history==null?new ProfileOwnedTask(platform,target,generation,ProfileBrokerHostTest.REQUEST,7)
                :new ProfileOwnedTask(platform,target,generation,ProfileBrokerHostTest.REQUEST,7,history);
        owned.prepare();owned.beforeDispatch();platform.io.launch();owned.accepted(0);
        if(!owned.observe())throw new AssertionError("actual producer did not retain its new profile leaf");
    }
    public WindowOwnership window(int windowId,long at)throws Exception{
        if(finished||at<platform.io.now)throw new AssertionError("producer window clock/lifetime differs");
        platform.io.now=at;return owned.window(windowId,300,at+1000);
    }
    public JSONObject retire(long at,boolean physicalChange)throws Exception{
        if(finished||at<platform.io.now)throw new AssertionError("producer retirement repeated or clock reversed");
        platform.io.now=at;if(physicalChange)platform.current=ForegroundConcurrencyHostTest.raw(1);
        if(!owned.observe())throw new AssertionError("actual producer lost its retained profile leaf");
        owned.retire(at+1000);finished=true;
        if(!owned.cleanupKnown())throw new AssertionError("actual producer did not prove owned cleanup");
        return new JSONObject(owned.cleanupEvidence());
    }
    public long now(){return platform.io.now;}
    public List<String> mutations(){return java.util.Collections.unmodifiableList(platform.io.mutations);}
}
