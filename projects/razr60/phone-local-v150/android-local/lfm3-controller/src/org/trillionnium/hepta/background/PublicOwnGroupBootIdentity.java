package org.trillionnium.hepta.background;

/** Bounded actual boot-count comparison for the root framework constructor.
 * The scope supplies only the expected value. The existing command owner supplies
 * the observed value after successful exit, bounded canonical output, and EOF.
 * No default, cached value, supplied receipt, or unavailable read can satisfy it. */
final class PublicOwnGroupBootIdentity {
    private static final long MAX_READ_MS=2000;
    private PublicOwnGroupBootIdentity(){}
    static void requireCurrent(ProfileRecoveryBootCount reader,int expected,long now,long deadline)throws Exception{
        if(reader==null)throw new BrokerProtocol.Refusal("PUBLIC_SCOPE_BOOT_READER_REQUIRED");
        if(expected<0)throw new BrokerProtocol.Refusal("PUBLIC_SCOPE_BOOT_CHANGED");
        if(now<0||now>Long.MAX_VALUE-MAX_READ_MS||deadline<=now)
            throw new BrokerProtocol.Refusal("PUBLIC_SCOPE_BOOT_DEADLINE");
        int actual=reader.read(Math.min(deadline,now+MAX_READ_MS));
        if(actual!=expected)throw new BrokerProtocol.Refusal("PUBLIC_SCOPE_BOOT_CHANGED");
    }
}
