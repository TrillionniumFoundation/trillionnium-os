/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.trillionnium.platform.internal;

import android.content.Context;
import android.util.Slog;

import org.trillionnium.capabilitylease.CapabilityLeaseBrokerNames;

import trillionnium.app.TrillionniumContextConstants;

/**
 * Lifecycle owner for the role-separated capability-lease broker transport.
 *
 * <p>The production constructor deliberately has no fallback authority.  The service is present
 * in the product lifecycle, but publishes nothing until a fully enrolled broker instance is
 * supplied by the OS-owned product authority.  This prevents a disabled trust file, development
 * signer, or caller-controlled value from turning the consent UI into an authorization oracle.</p>
 */
public final class CapabilityLeaseBrokerService extends TrillionniumSystemService {
    private static final String TAG = "TrillionniumLeaseBroker";

    /** A fully constructed broker and caller verifier; never synthesized from a request. */
    static final class Enrollment {
        final CapabilityLeaseBrokerServiceFacades facades;

        Enrollment(CapabilityLeasePendingBroker broker,
                CapabilityLeaseBrokerServiceFacades.CallerVerifier verifier) {
            if (broker == null || verifier == null) {
                throw new IllegalArgumentException("incomplete capability-lease enrollment");
            }
            facades = new CapabilityLeaseBrokerServiceFacades(broker, verifier);
        }
    }

    interface EnrollmentSource {
        Enrollment load(Context context) throws Exception;
    }

    private final EnrollmentSource mEnrollmentSource;

    public CapabilityLeaseBrokerService(Context context) {
        this(context, CapabilityLeaseBrokerProductEnrollment::load);
    }

    CapabilityLeaseBrokerService(Context context, EnrollmentSource enrollmentSource) {
        super(context);
        if (enrollmentSource == null) {
            throw new IllegalArgumentException("missing capability-lease enrollment source");
        }
        mEnrollmentSource = enrollmentSource;
    }

    @Override
    public String getFeatureDeclaration() {
        return TrillionniumContextConstants.Features.CAPABILITY_LEASE;
    }

    @Override
    public void onStart() {
        final Enrollment enrollment;
        try {
            enrollment = mEnrollmentSource.load(getContext());
        } catch (Exception unavailable) {
            Slog.w(TAG, "capability-lease enrollment unavailable; broker held closed");
            return;
        }
        if (enrollment == null || enrollment.facades == null) {
            Slog.w(TAG, "capability-lease enrollment incomplete; broker held closed");
            return;
        }
        publishBinderService(
                CapabilityLeaseBrokerNames.UI,
                new CapabilityLeaseUiBrokerBinder(enrollment.facades.ui));
        Slog.i(TAG, "capability-lease issuer transport published");
    }
}
