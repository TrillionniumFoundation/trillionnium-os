package org.trillionnium.hepta.displayprobe;

import java.io.IOException;

public final class OwnedDisplayPowerLeaseTest {
    private static int cases, checks;
    private interface Action { void run() throws Exception; }
    private static void check(boolean value) {
        checks++;
        if (!value) throw new AssertionError("check " + checks);
    }
    private static void refused(Action action) throws Exception {
        checks++;
        try { action.run(); } catch (SecurityException | IOException expected) { return; }
        throw new AssertionError("unproved lease accepted");
    }
    private static void run(String name, Action action) throws Exception {
        action.run(); cases++; System.out.println("PASS " + name);
    }
    private static final class Fake implements OwnedDisplayPowerLease.Platform, OwnedDisplayPowerLease.Clock,
            OwnedDisplayPowerLease.ScreenLock {
        long now = 1000, timeout, advanceOnAcquire;
        int factories, acquireCalls, releases, requestedId = -1, reads;
        boolean held, failCreate, failAcquireAfterHeld, failRelease, denyHeld, failRead;
        OwnedDisplayPowerLease.Scope scope = scope(210, 2, "owned-unique", 2,
            new int[] {0, 1, 210}, new int[] {0, 1, 2});
        OwnedDisplayPowerLease.Scope afterAcquire;
        @Override public long elapsedRealtime() { return now; }
        @Override public OwnedDisplayPowerLease.Scope readScope() throws IOException {
            reads++; if (failRead) throw new IOException("read unavailable");
            return acquireCalls > 0 && afterAcquire != null ? afterAcquire : scope;
        }
        @Override public OwnedDisplayPowerLease.ScreenLock newScreenLock(int id) throws IOException {
            factories++; requestedId = id;
            if (failCreate) throw new IOException("three-argument API unavailable");
            return this;
        }
        @Override public void acquire(long millis) throws IOException {
            acquireCalls++; timeout = millis; held = !denyHeld; now += advanceOnAcquire;
            if (failAcquireAfterHeld) throw new IOException("delivery failed after acquire");
        }
        @Override public boolean isHeld() { return held; }
        @Override public void release() throws IOException {
            releases++; if (failRelease) throw new IOException("release unknown"); held = false;
        }
        OwnedDisplayPowerLease lease() {
            return new OwnedDisplayPowerLease(this, this, 210, 2, "owned-unique", 901000);
        }
    }
    private static OwnedDisplayPowerLease.Scope scope(int id, int group, String unique, int state,
            int[] ids, int[] groups) {
        int[] types=ids==null?null:new int[ids.length];
        if(ids!=null)for(int i=0;i<ids.length;i++)types[i]=ids[i]==0||ids[i]==1?1:5;
        return new OwnedDisplayPowerLease.Scope(id, group, unique, state, ids, groups, types);
    }
    private static final class Initial implements OwnedDisplayPowerLease.InitialWait {
        final Fake fake;
        OwnedDisplayPowerLease.Scope[] next = new OwnedDisplayPowerLease.Scope[0];
        int observations, pauses, firstState = -1, lastState = -1;
        long advanceOnObservation;
        boolean interrupted;
        Initial(Fake fake) { this.fake = fake; }
        @Override public void observed(OwnedDisplayPowerLease.Scope actual, long elapsedMs) {
            if (fake.factories != 0 || fake.acquireCalls != 0 || elapsedMs != fake.now)
                throw new AssertionError("readiness is not a power operation");
            if (observations++ == 0) firstState = actual.state;
            lastState = actual.state;
            fake.now += advanceOnObservation;
        }
        @Override public void pause(long millis) throws InterruptedException {
            if (interrupted) throw new InterruptedException("initial wait interrupted");
            if (millis <= 0 || millis > 25) throw new AssertionError("unbounded readiness pause");
            fake.now += millis;
            if (pauses < next.length) fake.scope = next[pauses];
            pauses++;
        }
    }
    private static OwnedDisplayPowerLease.Scope initialState(int state) {
        return scope(210, 2, "owned-unique", state, new int[] {0, 1, 210}, new int[] {0, 1, 2});
    }
    public static void main(String[] args) throws Exception {
        run("exact-created-display-stays-held-past-original-eight-second-timeout", () -> {
            Fake f = new Fake(); OwnedDisplayPowerLease lease = f.lease(); lease.acquire();
            check(f.requestedId == 210 && f.factories == 1 && f.acquireCalls == 1);
            check(f.timeout == 900000 && lease.deadlineElapsedMs == 901000);
            f.now += 9000; lease.requireLive();
            check(lease.isHeld() && f.releases == 0 && f.factories == 1);
            lease.close(); lease.close();
            check(f.releases == 1 && !f.held && !lease.isHeld());
        });
        run("invalid-default-and-physical-display-ids-never-reach-power-api", () -> {
            for (int id : new int[] {-1, 0, 1}) {
                Fake f = new Fake();
                refused(() -> new OwnedDisplayPowerLease(f, f, id, 2, "owned-unique", 901000));
                check(f.factories == 0 && f.acquireCalls == 0);
            }
        });
        run("default-or-physical-groups-never-reach-power-api", () -> {
            Fake f = new Fake();
            refused(() -> new OwnedDisplayPowerLease(f, f, 210, 0, "owned-unique", 901000));
            f.scope = scope(210, 2, "owned-unique", 2, new int[] {0, 1, 210}, new int[] {2, 1, 2});
            refused(() -> f.lease().acquire()); check(f.factories == 0);
            f.scope = scope(210, 2, "owned-unique", 2, new int[] {0, 1, 210}, new int[] {0, 2, 2});
            refused(() -> f.lease().acquire()); check(f.factories == 0);
        });
        run("another-virtual-display-in-the-group-preserves-the-exact-token", () -> {
            Fake f = new Fake();
            f.scope = scope(210, 2, "owned-unique", 2, new int[] {0, 1, 210, 211}, new int[] {0, 1, 2, 2});
            OwnedDisplayPowerLease lease=f.lease();lease.acquire();lease.requireLive();
            check(f.factories==1&&f.requestedId==210&&f.held);
            check(java.util.Arrays.equals(lease.groupMembers(),new int[]{210,211}));
            lease.close();check(f.releases==1&&!f.held);
        });
        run("missing-physical-display-and-duplicate-or-incomplete-census-refused", () -> {
            int[][] ids = {{0, 210, 211}, {1, 210, 211}, {0, 1, 210, 210}, {0, 1, 210}, {-1, 1, 210}};
            int[][] groups = {{0, 2, 3}, {1, 2, 3}, {0, 1, 2, 2}, {0, 1}, {0, 1, 2}};
            for (int i = 0; i < ids.length; i++) {
                Fake f = new Fake(); f.scope = scope(210, 2, "owned-unique", 2, ids[i], groups[i]);
                refused(() -> f.lease().acquire()); check(f.factories == 0);
            }
        });
        run("wrong-id-group-and-generation-identity-refused", () -> {
            for (OwnedDisplayPowerLease.Scope bad : new OwnedDisplayPowerLease.Scope[] {
                scope(211, 2, "owned-unique", 2, new int[] {0, 1, 211}, new int[] {0, 1, 2}),
                scope(210, 3, "owned-unique", 2, new int[] {0, 1, 210}, new int[] {0, 1, 3}),
                scope(210, 2, "replacement", 2, new int[] {0, 1, 210}, new int[] {0, 1, 2})}) {
                Fake f = new Fake(); f.scope = bad;
                refused(() -> f.lease().acquire()); check(f.factories == 0);
            }
        });
        run("already-off-created-display-is-refused-without-wake-or-fallback", () -> {
            Fake f = new Fake(); f.scope = scope(210, 2, "owned-unique", 1, new int[] {0, 1, 210}, new int[] {0, 1, 2});
            refused(() -> f.lease().acquire()); check(f.factories == 0 && f.acquireCalls == 0);
        });
        run("absolute-deadline-expired-or-extended-is-refused", () -> {
            for (long deadline : new long[] {0, 1000, 901001, Long.MAX_VALUE}) {
                Fake f = new Fake();
                refused(() -> new OwnedDisplayPowerLease(f, f, 210, 2, "owned-unique", deadline));
                check(f.factories == 0);
            }
        });
        run("three-argument-api-failure-has-no-global-fallback", () -> {
            Fake f = new Fake(); f.failCreate = true;
            refused(() -> f.lease().acquire());
            check(f.factories == 1 && f.requestedId == 210 && f.acquireCalls == 0);
        });
        run("acquire-exception-after-held-releases-owned-lock", () -> {
            Fake f = new Fake(); f.failAcquireAfterHeld = true;
            refused(() -> f.lease().acquire()); check(f.releases == 1 && !f.held);
        });
        run("unheld-result-does-not-claim-success", () -> {
            Fake f = new Fake(); f.denyHeld = true;
            refused(() -> f.lease().acquire()); check(f.acquireCalls == 1 && !f.held);
        });
        run("post-acquire-physical-group-census-change-releases-lock", () -> {
            Fake f = new Fake();
            f.afterAcquire = scope(210, 2, "owned-unique", 2, new int[] {0, 1, 210, 211}, new int[] {2, 1, 2, 2});
            refused(() -> f.lease().acquire()); check(f.releases == 1 && !f.held);
        });
        run("post-acquire-off-state-releases-lock", () -> {
            Fake f = new Fake(); f.afterAcquire = scope(210, 2, "owned-unique", 1, new int[] {0, 1, 210}, new int[] {0, 1, 2});
            refused(() -> f.lease().acquire()); check(f.releases == 1 && !f.held);
        });
        run("deadline-during-acquire-or-during-live-check-releases-lock", () -> {
            Fake a = new Fake(); a.advanceOnAcquire = 900000;
            refused(() -> a.lease().acquire()); check(a.releases == 1 && !a.held);
            Fake b = new Fake(); OwnedDisplayPowerLease lease = b.lease(); lease.acquire(); b.now = 901000;
            refused(lease::requireLive); check(b.releases == 1 && !b.held);
        });
        run("readback-error-after-acquire-releases-and-prevents-renewal", () -> {
            Fake f = new Fake(); OwnedDisplayPowerLease lease = f.lease(); lease.acquire(); f.failRead = true;
            refused(lease::requireLive); check(f.releases == 1 && !f.held);
            refused(lease::acquire); check(f.factories == 1 && f.acquireCalls == 1);
        });
        run("release-error-remains-error-not-a-cleanup-proof", () -> {
            Fake f = new Fake(); OwnedDisplayPowerLease lease = f.lease(); lease.acquire(); f.failRelease = true;
            refused(lease::close); check(f.held && f.releases == 1);
            refused(lease::requireLive);
        });
        run("initial-unknown-off-on-within-original-budget-before-exact-acquire", () -> {
            Fake f = new Fake(); f.scope = initialState(0);
            Initial wait = new Initial(f); wait.next = new OwnedDisplayPowerLease.Scope[] {initialState(1), initialState(2)};
            OwnedDisplayPowerLease lease = f.lease(); lease.awaitInitialOn(6000, wait);
            check(wait.observations == 3 && wait.pauses == 2 && wait.firstState == 0 && wait.lastState == 2);
            check(f.factories == 0 && f.acquireCalls == 0 && lease.deadlineElapsedMs == 901000);
            lease.acquire();
            check(f.factories == 1 && f.requestedId == 210 && f.timeout == 899950 && lease.isHeld());
            lease.close(); check(f.releases == 1 && !f.held);
        });
        run("initial-off-timeout-has-zero-power-operations-and-no-lifetime-extension", () -> {
            Fake f = new Fake(); f.scope = initialState(1); Initial wait = new Initial(f);
            OwnedDisplayPowerLease lease = f.lease(); refused(() -> lease.awaitInitialOn(1100, wait));
            check(f.now == 1100 && wait.observations == 4 && wait.pauses == 4);
            check(f.factories == 0 && f.acquireCalls == 0 && lease.deadlineElapsedMs == 901000);
            lease.close(); check(f.releases == 0);
        });
        run("changed-identity-during-readiness-is-refused-before-power-api", () -> {
            Fake f = new Fake(); f.scope = initialState(0); Initial wait = new Initial(f);
            wait.next = new OwnedDisplayPowerLease.Scope[] {
                scope(210, 2, "replacement", 2, new int[] {0, 1, 210}, new int[] {0, 1, 2})};
            refused(() -> f.lease().awaitInitialOn(6000, wait));
            check(wait.observations == 1 && wait.pauses == 1 && f.factories == 0);
        });
        run("initial-unknown-still-requires-complete-isolated-census", () -> {
            for (OwnedDisplayPowerLease.Scope bad : new OwnedDisplayPowerLease.Scope[] {
                scope(210, 2, "owned-unique", 0, new int[] {0, 1, 210, 211}, new int[] {2, 1, 2, 2}),
                scope(210, 2, "owned-unique", 1, new int[] {0, 210, 211}, new int[] {0, 2, 3})}) {
                Fake f = new Fake(); f.scope = bad; Initial wait = new Initial(f);
                refused(() -> f.lease().awaitInitialOn(6000, wait));
                check(wait.observations == 0 && f.factories == 0 && f.acquireCalls == 0);
            }
        });
        run("readiness-success-cannot-bypass-fresh-on-check-in-original-acquire", () -> {
            Fake f = new Fake(); Initial wait = new Initial(f); OwnedDisplayPowerLease lease = f.lease();
            lease.awaitInitialOn(6000, wait); f.scope = initialState(1);
            refused(lease::acquire); check(f.factories == 0 && f.acquireCalls == 0 && !lease.isHeld());
        });
        run("invalid-or-late-initial-deadline-never-grants-power", () -> {
            for (long end : new long[] {1000, 6001, 901001}) {
                Fake f = new Fake(); Initial wait = new Initial(f);
                refused(() -> f.lease().awaitInitialOn(end, wait));
                check(wait.observations == 0 && f.factories == 0);
            }
            Fake f = new Fake(); Initial wait = new Initial(f); wait.advanceOnObservation = 5000;
            refused(() -> f.lease().awaitInitialOn(6000, wait)); check(f.factories == 0 && wait.observations == 1);
        });
        run("initial-read-failure-and-interruption-are-not-retried-as-success", () -> {
            Fake a = new Fake(); a.failRead = true; Initial first = new Initial(a);
            refused(() -> a.lease().awaitInitialOn(6000, first)); check(first.observations == 0 && a.factories == 0);
            Fake b = new Fake(); b.scope = initialState(0); Initial second = new Initial(b); second.interrupted = true;
            try { b.lease().awaitInitialOn(6000, second); throw new AssertionError("interrupted wait accepted"); }
            catch (InterruptedException expected) { check(b.factories == 0 && second.observations == 1); }
        });
        run("dozing-is-not-treated-as-an-initial-on-or-unknown-state", () -> {
            Fake f = new Fake(); f.scope = initialState(3); Initial wait = new Initial(f);
            refused(() -> f.lease().awaitInitialOn(6000, wait));
            check(wait.observations == 1 && wait.pauses == 0 && f.factories == 0);
        });
        run("virtual-peers-join-and-leave-without-token-renewal", () -> {
            Fake f=new Fake();OwnedDisplayPowerLease lease=f.lease();lease.acquire();
            f.scope=scope(210,2,"owned-unique",2,new int[]{0,1,210,211},new int[]{0,1,2,2});lease.requireLive();
            check(java.util.Arrays.equals(lease.groupMembers(),new int[]{210,211}));
            f.scope=scope(210,2,"owned-unique",2,new int[]{0,1,210},new int[]{0,1,2});lease.requireLive();
            check(f.factories==1&&f.acquireCalls==1&&f.releases==0);
            check(java.util.Arrays.equals(lease.groupMembers(),new int[]{210}));lease.close();
        });
        run("release-of-one-shared-group-token-leaves-the-peer-token-held", () -> {
            Fake a=new Fake(),b=new Fake();
            a.scope=scope(210,2,"owned-unique",2,new int[]{0,1,210,211},new int[]{0,1,2,2});
            b.scope=scope(211,2,"peer-unique",2,new int[]{0,1,210,211},new int[]{0,1,2,2});
            OwnedDisplayPowerLease first=a.lease(),second=new OwnedDisplayPowerLease(b,b,211,2,"peer-unique",901000);
            first.acquire();second.acquire();first.close();second.requireLive();
            check(a.releases==1&&!a.held&&b.releases==0&&b.held);check(b.requestedId==211);
            second.close();check(b.releases==1&&!b.held);
        });
        run("unknown-or-physical-peer-type-never-reaches-the-power-api", () -> {
            for(int type:new int[]{0,1,2,3,4}){
                Fake f=new Fake();f.scope=new OwnedDisplayPowerLease.Scope(210,2,"owned-unique",2,
                    new int[]{0,1,210,211},new int[]{0,1,2,2},new int[]{1,1,5,type});
                refused(()->f.lease().acquire());check(f.factories==0);
            }
        });
        run("missing-or-mismatched-type-census-never-reaches-the-power-api", () -> {
            for(int[] types:new int[][]{null,new int[]{1,1},new int[]{5,1,5},new int[]{1,5,5}}){
                Fake f=new Fake();f.scope=new OwnedDisplayPowerLease.Scope(210,2,"owned-unique",2,
                    new int[]{0,1,210},new int[]{0,1,2},types);
                refused(()->f.lease().acquire());check(f.factories==0);
            }
        });
        run("physical-peer-arrival-retires-only-the-owned-token", () -> {
            Fake f=new Fake();OwnedDisplayPowerLease lease=f.lease();lease.acquire();
            f.scope=new OwnedDisplayPowerLease.Scope(210,2,"owned-unique",2,
                new int[]{0,1,210,211},new int[]{0,1,2,2},new int[]{1,1,5,1});
            refused(lease::requireLive);check(f.releases==1&&!f.held&&f.factories==1);
        });
        run("virtual-peer-readiness-keeps-original-deadline-and-live-census", () -> {
            Fake f=new Fake();f.scope=initialState(1);Initial wait=new Initial(f);
            wait.next=new OwnedDisplayPowerLease.Scope[]{scope(210,2,"owned-unique",2,
                new int[]{0,1,210,211},new int[]{0,1,2,2})};
            OwnedDisplayPowerLease lease=f.lease();lease.awaitInitialOn(6000,wait);lease.acquire();
            check(wait.pauses==1&&f.timeout==899975&&lease.deadlineElapsedMs==901000);
            check(java.util.Arrays.equals(lease.groupMembers(),new int[]{210,211}));lease.close();
        });
        System.out.println("RESULT cases=" + cases + " checks=" + checks + " all_pass=true phone_operations=0");
    }
}
