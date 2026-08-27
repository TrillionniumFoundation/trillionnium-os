/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.trillionnium.platform.internal;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Binder;
import android.os.Process;
import android.os.SELinux;
import android.os.UserHandle;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.EnumMap;
import java.util.Map;

/** Captures and verifies every external broker transaction against immutable product pins. */
final class CapabilityLeaseBinderCallerVerifier {
    private final PackageManager mPackageManager;
    private final Map<CapabilityLeaseBrokerCallerPolicy.Role,
            CapabilityLeaseBrokerCallerPolicy.CallerPin> mPins;

    CapabilityLeaseBinderCallerVerifier(PackageManager packageManager,
            Map<CapabilityLeaseBrokerCallerPolicy.Role,
                    CapabilityLeaseBrokerCallerPolicy.CallerPin> pins) {
        if (packageManager == null || pins == null
                || pins.size() != CapabilityLeaseBrokerCallerPolicy.Role.values().length) {
            throw new IllegalArgumentException("incomplete broker caller verifier");
        }
        mPackageManager = packageManager;
        mPins = new EnumMap<>(CapabilityLeaseBrokerCallerPolicy.Role.class);
        mPins.putAll(pins);
        for (CapabilityLeaseBrokerCallerPolicy.Role role
                : CapabilityLeaseBrokerCallerPolicy.Role.values()) {
            CapabilityLeaseBrokerCallerPolicy.CallerPin pin = mPins.get(role);
            if (pin == null || pin.role != role) {
                throw new IllegalArgumentException("invalid broker caller role pin");
            }
        }
    }

    CapabilityLeaseBrokerCallerPolicy.VerifiedCaller verify(
            CapabilityLeaseBrokerCallerPolicy.Operation operation) {
        if (operation == null) {
            throw new SecurityException("capability_lease_broker_operation_denied");
        }
        // Capture the remote Binder identity before temporarily adopting system_server identity
        // for package-manager reads. The verified result is immutable evidence for off-thread work.
        int uid = Binder.getCallingUid();
        int pid = Binder.getCallingPid();
        CapabilityLeaseBrokerCallerPolicy.CallerPin pin = mPins.get(operation.requiredRole);
        long identity = Binder.clearCallingIdentity();
        try {
            String[] packages = mPackageManager.getPackagesForUid(uid);
            if (packages == null || packages.length != 1
                    || !pin.packageName.equals(packages[0])
                    || mPackageManager.getPackageUidAsUser(pin.packageName, 0) != uid) {
                throw denied();
            }
            PackageInfo info = mPackageManager.getPackageInfo(pin.packageName,
                    PackageManager.PackageInfoFlags.of(
                            PackageManager.GET_SIGNING_CERTIFICATES));
            SigningInfo signingInfo = info.signingInfo;
            Signature[] signers = signingInfo == null
                    ? null : signingInfo.getApkContentsSigners();
            if (signingInfo == null || signingInfo.hasMultipleSigners()
                    || signers == null || signers.length != 1) {
                throw denied();
            }
            String firstContext = SELinux.getPidContext(pid);
            String secondContext = SELinux.getPidContext(pid);
            if (firstContext == null || !firstContext.equals(secondContext)) throw denied();
            CapabilityLeaseBrokerCallerPolicy.ObservedCaller observed =
                    new CapabilityLeaseBrokerCallerPolicy.ObservedCaller(
                            uid, pid, UserHandle.getUserId(uid), Process.isApplicationUid(uid),
                            packages[0], packages.length, sha256(signers[0].toByteArray()),
                            firstContext);
            return CapabilityLeaseBrokerCallerPolicy.verify(operation, pin, observed);
        } catch (PackageManager.NameNotFoundException denied) {
            throw denied();
        } finally {
            Binder.restoreCallingIdentity(identity);
        }
    }

    private static String sha256(byte[] value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
            char[] output = new char[digest.length * 2];
            char[] alphabet = "0123456789abcdef".toCharArray();
            for (int index = 0; index < digest.length; index++) {
                int item = digest[index] & 0xff;
                output[index * 2] = alphabet[item >>> 4];
                output[index * 2 + 1] = alphabet[item & 0x0f];
            }
            return new String(output);
        } catch (NoSuchAlgorithmException impossible) {
            throw new AssertionError("SHA-256 unavailable", impossible);
        }
    }

    private static SecurityException denied() {
        return new SecurityException("capability_lease_broker_caller_denied");
    }
}
