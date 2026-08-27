/*
 * SPDX-FileCopyrightText: 2015, The CyanogenMod Project
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package trillionnium.app;

import android.annotation.SdkConstant;

/**
 * @hide
 * TODO: We need to somehow make these managers accessible via getSystemService
 */
public final class TrillionniumContextConstants {

    /**
     * @hide
     */
    private TrillionniumContextConstants() {
        // Empty constructor
    }

    /**
     * Use with {@link android.content.Context#getSystemService} to retrieve a
     * {@link trillionnium.app.ProfileManager} for informing the user of
     * background events.
     *
     * @see android.content.Context#getSystemService
     * @see trillionnium.app.ProfileManager
     *
     * @hide
     */
    public static final String TRILLIONNIUM_PROFILE_SERVICE = "profile";

    /**
     * Use with {@link android.content.Context#getSystemService} to retrieve a
     * {@link trillionnium.hardware.TrillionniumHardwareManager} to manage the extended
     * hardware features of the device.
     *
     * @see android.content.Context#getSystemService
     * @see trillionnium.hardware.TrillionniumHardwareManager
     *
     * @hide
     */
    public static final String TRILLIONNIUM_HARDWARE_SERVICE = "trillionniumhardware";

    /**
     * Manages display color adjustments
     *
     * @hide
     */
    public static final String TRILLIONNIUM_LIVEDISPLAY_SERVICE = "trillionniumlivedisplay";

    /**
     * Use with {@link android.content.Context#getSystemService} to retrieve a
     * {@link trillionnium.trust.TrustInterface} to access the Trust interface.
     *
     * @see android.content.Context#getSystemService
     * @see trillionnium.trust.TrustInterface
     *
     * @hide
     */
    public static final String TRILLIONNIUM_TRUST_INTERFACE = "trillionniumtrust";

    /**
     * Use with {@link android.content.Context#getSystemService} to retrieve a
     * {@link trillionnium.health.HealthInterface} to access the Health interface.
     *
     * @see android.content.Context#getSystemService
     * @see trillionnium.health.HealthInterface
     *
     * @hide
     */
    public static final String TRILLIONNIUM_HEALTH_INTERFACE = "trillionniumhealth";

    /**
     * Update power menu (GlobalActions)
     *
     * @hide
     */
    public static final String TRILLIONNIUM_GLOBAL_ACTIONS_SERVICE = "trillionniumglobalactions";

    /**
     * Features supported by the Trillionnium SDK.
     */
    public static class Features {
        /**
         * Feature for the direct, closed Trillionnium Agent System API socket.
         *
         * @hide
         */
        @SdkConstant(SdkConstant.SdkConstantType.FEATURE)
        public static final String AGENT_SYSTEM_API = "org.trillionnium.agent.system_api";

        /**
         * Feature gate for the production-enrolled capability-lease broker.
         *
         * <p>The current product intentionally does not declare this feature until hardware
         * rollback state and all signer/provider pins are enrolled.</p>
         *
         * @hide
         */
        @SdkConstant(SdkConstant.SdkConstantType.FEATURE)
        public static final String CAPABILITY_LEASE =
                "org.trillionnium.agent.capability_lease";

        /**
         * Feature for {@link PackageManager#getSystemAvailableFeatures} and
         * {@link PackageManager#hasSystemFeature}: The device includes the hardware abstraction
         * framework service utilized by the Trillionnium SDK.
         */
        @SdkConstant(SdkConstant.SdkConstantType.FEATURE)
        public static final String HARDWARE_ABSTRACTION = "org.trillionnium.hardware";

        /**
         * Feature for {@link PackageManager#getSystemAvailableFeatures} and
         * {@link PackageManager#hasSystemFeature}: The device includes the Trillionnium profiles
         * service utilized by the Trillionnium SDK.
         */
        @SdkConstant(SdkConstant.SdkConstantType.FEATURE)
        public static final String PROFILES = "org.trillionnium.profiles";

        /**
         * Feature for {@link PackageManager#getSystemAvailableFeatures} and
         * {@link PackageManager#hasSystemFeature}: The device includes the LiveDisplay service
         * utilized by the Trillionnium SDK.
         */
        @SdkConstant(SdkConstant.SdkConstantType.FEATURE)
        public static final String LIVEDISPLAY = "org.trillionnium.livedisplay";

        /**
         * Feature for {@link PackageManager#getSystemAvailableFeatures} and
         * {@link PackageManager#hasSystemFeature}: The device includes the Trillionnium trust
         * service utilized by the Trillionnium SDK.
         */
        @SdkConstant(SdkConstant.SdkConstantType.FEATURE)
        public static final String TRUST = "org.trillionnium.trust";

        /**
         * Feature for {@link PackageManager#getSystemAvailableFeatures} and
         * {@link PackageManager#hasSystemFeature}: The device includes the Trillionnium settings
         * service utilized by the Trillionnium SDK.
         */
        @SdkConstant(SdkConstant.SdkConstantType.FEATURE)
        public static final String SETTINGS = "org.trillionnium.settings";

        /**
         * Feature for {@link PackageManager#getSystemAvailableFeatures} and
         * {@link PackageManager#hasSystemFeature}: The device includes the Trillionnium
         * globalactions service utilized by the Trillionnium SDK and TrillionniumParts.
         */
        @SdkConstant(SdkConstant.SdkConstantType.FEATURE)
        public static final String GLOBAL_ACTIONS = "org.trillionnium.globalactions";

        /**
         * Feature for {@link PackageManager#getSystemAvailableFeatures} and
         * {@link PackageManager#hasSystemFeature}: The device includes the Trillionnium health
         * service utilized by the Trillionnium SDK and TrillionniumParts.
         */
        @SdkConstant(SdkConstant.SdkConstantType.FEATURE)
        public static final String HEALTH = "org.trillionnium.health";
    }
}
