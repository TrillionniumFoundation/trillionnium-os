//! Variant-local stable-principal and active-launcher binding for Codex.
//!
//! The stable principal registry is the only authority for provider, agent,
//! replay namespace, UID/GID, SELinux domain, and runtime adapter. Executable
//! identity is deliberately outside that registry. The separately compiled P0
//! userdebug lane binds it to the measured launcher carried by its receipt.
//! Default/product builds currently have no compile-time launcher identity.
//! Their execution paths must supply a fresh OS-held file-description
//! measurement instead of falling back to the legacy descriptor digest.

use trillionnium_os_types::AgentRegistration;
use trillionnium_os_types::agent_principal_registry::{
    self, AgentStablePrincipal, CODEX_STABLE_PRINCIPAL,
};

#[cfg(feature = "p0-launch-package-device-conformance")]
pub(crate) const P01_CODEX_LAUNCHER_SHA256: &str = env!("TRILLIONNIUM_P01_CODEX_LAUNCHER_SHA256");
#[cfg(feature = "p0-launch-package-device-conformance")]
pub(crate) const P01_DAEMON_BUILD_BINDING_SHA256: &str =
    env!("TRILLIONNIUM_P01_DAEMON_BUILD_BINDING_SHA256");

#[cfg(feature = "p0-launch-package-device-conformance")]
mod p01_daemon_measurement {
    include!(concat!(env!("OUT_DIR"), "/p01_daemon_measurement_v4.rs"));
}

/// Read and validate the linker-retained P0 measurement record before the
/// daemon accepts any manifest or Agent API connection. The separately
/// generated record gives product tooling a stable ELF section to inspect;
/// this check binds those physical bytes back to the exact values used by the
/// runtime launcher and receipt paths.
pub(crate) fn compiled_measurement_is_exact() -> bool {
    #[cfg(not(feature = "p0-launch-package-device-conformance"))]
    {
        true
    }
    #[cfg(feature = "p0-launch-package-device-conformance")]
    {
        let expected = concat!(
            "schema=org.trillionnium.p01-userdebug-daemon-measurement.v4\n",
            "variant=",
            env!("TRILLIONNIUM_P01_CONFORMANCE_BUILD_VARIANT"),
            "\ndaemon_build_binding_sha256=",
            env!("TRILLIONNIUM_P01_DAEMON_BUILD_BINDING_SHA256"),
            "\nlauncher_sha256=",
            env!("TRILLIONNIUM_P01_CODEX_LAUNCHER_SHA256"),
            "\nsystem_api_sha256=",
            env!("TRILLIONNIUM_P01_SYSTEM_API_SHA256"),
            "\n",
        );
        p01_daemon_measurement::P01_MEASUREMENT_SCHEMA
            == "org.trillionnium.p01-userdebug-daemon-measurement.v4"
            && std::hint::black_box(
                &p01_daemon_measurement::TRILLIONNIUM_P01_DAEMON_MEASUREMENT_V4[..],
            ) == expected.as_bytes()
    }
}

/// Return the separately measured active launcher identity for this build.
///
/// Product/default intentionally returns `None`: it must obtain the active
/// executable digest from the OS-held runtime measurement path, never inherit
/// one from the legacy descriptor registry.
pub(crate) fn active_launcher_identity(principal: &AgentStablePrincipal) -> Option<&'static str> {
    #[cfg(not(feature = "p0-launch-package-device-conformance"))]
    {
        let _ = principal;
        None
    }
    #[cfg(feature = "p0-launch-package-device-conformance")]
    {
        (principal == &CODEX_STABLE_PRINCIPAL).then_some(P01_CODEX_LAUNCHER_SHA256)
    }
}

pub(crate) fn compile_time_launcher_authority_available() -> bool {
    active_launcher_identity(&CODEX_STABLE_PRINCIPAL).is_some()
}

/// Verify every stable field and its closed registry projection without
/// consulting executable identity.
pub(crate) fn matches_stable_registration(
    principal: &AgentStablePrincipal,
    registration: &AgentRegistration,
) -> bool {
    agent_principal_registry::from_provider_agent_pair(
        principal.provider_id,
        &registration.agent_id,
    ) == Some(principal)
        && agent_principal_registry::from_replay_namespace(principal.replay_namespace)
            == Some(principal)
        && agent_principal_registry::from_uid_gid(registration.peer_uid, registration.peer_gid)
            == Some(principal)
        && principal.matches_registration_fields(registration)
}

/// Match stable principal fields, then independently bind the registration to
/// a launcher digest measured by the caller from its held executable file
/// description. P01 additionally requires that measurement to equal its
/// compile-time build binding.
pub(crate) fn matches_registration_with_active_launcher(
    principal: &AgentStablePrincipal,
    registration: &AgentRegistration,
    measured_launcher_sha256: &str,
) -> bool {
    matches_stable_registration(principal, registration)
        && trillionnium_os_types::is_nonzero_lower_sha256(measured_launcher_sha256)
        && registration.identity_key_sha256 == measured_launcher_sha256
        && active_launcher_identity(principal)
            .is_none_or(|identity| measured_launcher_sha256 == identity)
}

pub(crate) fn stable_principal_from_registration(
    registration: &AgentRegistration,
) -> Option<&'static AgentStablePrincipal> {
    agent_principal_registry::from_agent_id(&registration.agent_id)
        .filter(|principal| matches_stable_registration(principal, registration))
}

pub(crate) fn from_registration_with_active_launcher(
    registration: &AgentRegistration,
    measured_launcher_sha256: &str,
) -> Option<&'static AgentStablePrincipal> {
    agent_principal_registry::from_agent_id(&registration.agent_id).filter(|principal| {
        matches_registration_with_active_launcher(principal, registration, measured_launcher_sha256)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use trillionnium_os_types::{
        AGENT_API_VERSION, AgentHealth, AgentNetworkPolicy, AgentRegistration,
    };

    fn registration(principal: &AgentStablePrincipal, identity: &str) -> AgentRegistration {
        AgentRegistration {
            api_version: AGENT_API_VERSION.to_string(),
            agent_id: principal.agent_id.to_string(),
            adapter: principal.runtime_adapter.to_string(),
            adapter_version: "p01-identity-test".to_string(),
            identity_key_sha256: identity.to_string(),
            peer_uid: principal.uid,
            peer_gid: principal.gid,
            selinux_domain: principal.agent_selinux_domain.to_string(),
            network_policy: AgentNetworkPolicy::PerRequest,
            enabled: true,
            health: AgentHealth::Ready,
            registered_at_unix_ms: 1,
            updated_at_unix_ms: 1,
        }
    }

    #[cfg(not(feature = "p0-launch-package-device-conformance"))]
    #[test]
    fn product_build_has_no_implicit_legacy_launcher_authority() {
        let legacy_descriptor_digest =
            "edcf9d31da8b48d29575115a7242691c1337174edf42573b7274b652a4cd571c";
        let measured_launcher =
            trillionnium_os_types::sha256_bytes(b"independently-measured-default-launcher");
        assert_ne!(measured_launcher, legacy_descriptor_digest);
        let registration = registration(&CODEX_STABLE_PRINCIPAL, &measured_launcher);
        assert!(matches_stable_registration(
            &CODEX_STABLE_PRINCIPAL,
            &registration
        ));
        assert!(!compile_time_launcher_authority_available());
        assert_eq!(active_launcher_identity(&CODEX_STABLE_PRINCIPAL), None);
        assert!(matches_registration_with_active_launcher(
            &CODEX_STABLE_PRINCIPAL,
            &registration,
            &measured_launcher,
        ));
        assert!(!matches_registration_with_active_launcher(
            &CODEX_STABLE_PRINCIPAL,
            &registration,
            &trillionnium_os_types::sha256_bytes(b"different-measured-launcher"),
        ));
        assert_eq!(
            stable_principal_from_registration(&registration),
            Some(&CODEX_STABLE_PRINCIPAL)
        );
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    #[test]
    fn p01_build_accepts_only_the_measured_codex_launcher() {
        assert!(compiled_measurement_is_exact());
        assert!(compile_time_launcher_authority_available());
        assert!(
            P01_DAEMON_BUILD_BINDING_SHA256.len() == 64
                && P01_DAEMON_BUILD_BINDING_SHA256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        let codex = registration(&CODEX_STABLE_PRINCIPAL, P01_CODEX_LAUNCHER_SHA256);
        assert!(matches_registration_with_active_launcher(
            &CODEX_STABLE_PRINCIPAL,
            &codex,
            P01_CODEX_LAUNCHER_SHA256,
        ));
        assert_eq!(
            from_registration_with_active_launcher(&codex, P01_CODEX_LAUNCHER_SHA256),
            Some(&CODEX_STABLE_PRINCIPAL)
        );

        let unmeasured = "edcf9d31da8b48d29575115a7242691c1337174edf42573b7274b652a4cd571c";
        assert_ne!(unmeasured, P01_CODEX_LAUNCHER_SHA256);
        assert!(!matches_registration_with_active_launcher(
            &CODEX_STABLE_PRINCIPAL,
            &registration(&CODEX_STABLE_PRINCIPAL, unmeasured),
            unmeasured,
        ));
    }

    #[test]
    fn launcher_identity_cannot_relax_any_stable_principal_field() {
        let identity = active_launcher_identity(&CODEX_STABLE_PRINCIPAL)
            .unwrap_or("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let base = registration(&CODEX_STABLE_PRINCIPAL, identity);
        for changed in [
            AgentRegistration {
                adapter: "unregistered-adapter".to_string(),
                ..base.clone()
            },
            AgentRegistration {
                peer_uid: base.peer_uid + 1,
                ..base.clone()
            },
            AgentRegistration {
                peer_gid: base.peer_gid + 1,
                ..base.clone()
            },
            AgentRegistration {
                selinux_domain: "u:r:unregistered_agent:s0".to_string(),
                ..base.clone()
            },
        ] {
            assert!(!matches_stable_registration(
                &CODEX_STABLE_PRINCIPAL,
                &changed
            ));
            assert!(!matches_registration_with_active_launcher(
                &CODEX_STABLE_PRINCIPAL,
                &changed,
                identity,
            ));
            assert_eq!(stable_principal_from_registration(&changed), None);
        }

        for changed_principal in [
            AgentStablePrincipal {
                provider_id: "substituted-provider",
                ..CODEX_STABLE_PRINCIPAL
            },
            AgentStablePrincipal {
                replay_namespace: "substituted-replay-namespace",
                ..CODEX_STABLE_PRINCIPAL
            },
        ] {
            assert!(!matches_stable_registration(&changed_principal, &base));
            assert!(!matches_registration_with_active_launcher(
                &changed_principal,
                &base,
                identity,
            ));
        }
    }
}
