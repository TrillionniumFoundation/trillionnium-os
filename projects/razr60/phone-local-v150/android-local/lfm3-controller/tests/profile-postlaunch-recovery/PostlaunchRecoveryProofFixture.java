package org.trillionnium.hepta.background;
import org.json.JSONObject;
/** Explicit synthetic reply factory. No Android or root operation. */
public final class PostlaunchRecoveryProofFixture {
 private PostlaunchRecoveryProofFixture(){}
 public static JSONObject reply(ProfilePostlaunchRecovery.Request r)throws Exception{return ProfilePostlaunchRecoveryHostTest.proof(r);}
}
