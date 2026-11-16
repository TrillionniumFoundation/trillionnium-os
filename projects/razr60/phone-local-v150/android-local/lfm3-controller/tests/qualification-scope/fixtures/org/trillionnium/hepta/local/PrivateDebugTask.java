package org.trillionnium.hepta.local;
/** Authorization IO fixture only; production nonce verification is unchanged and not tested here. */
public final class PrivateDebugTask {static String owner="打开设置";final String instruction=owner,nonceSha256="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";public static PrivateDebugTask consume(Object context,String nonce){if(!"synthetic-nonce".equals(nonce))throw new IllegalArgumentException("bad fixture nonce");return new PrivateDebugTask();}}
