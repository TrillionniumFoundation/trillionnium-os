use std::env;

use anyhow::{Context, Result, bail};
use rustix::io::Errno;
use rustix::thread::{
    CapabilitiesSecureBits, CapabilitySet, CapabilitySets, capabilities, capabilities_secure_bits,
    capability_is_in_ambient_set, capability_is_in_bounding_set, clear_ambient_capability_set,
    remove_capability_from_bounding_set, set_capabilities, set_capabilities_secure_bits,
};

const HARDENING_ENV: &str = "TRILLIONNIUM_ANDROID_AGENTD_CAPABILITY_HARDENING";
const ACTIVE_MARKER: &str = "TRILLIONNIUM_AGENTD_CAPABILITY_HARDENING_V1_ACTIVE";
const MAX_LINUX_CAPABILITY_BITS: u32 = 64;

fn long_lived_capabilities() -> CapabilitySet {
    CapabilitySet::CHOWN | CapabilitySet::KILL | CapabilitySet::SETGID | CapabilitySet::SETUID
}

fn startup_capabilities() -> CapabilitySet {
    long_lived_capabilities() | CapabilitySet::SETPCAP | CapabilitySet::SYS_CHROOT
}

fn required_secure_bits() -> CapabilitiesSecureBits {
    CapabilitiesSecureBits::NO_ROOT
        | CapabilitiesSecureBits::NO_ROOT_LOCKED
        | CapabilitiesSecureBits::NO_CAP_AMBIENT_RAISE
        | CapabilitiesSecureBits::NO_CAP_AMBIENT_RAISE_LOCKED
}

fn forbidden_secure_bits() -> CapabilitiesSecureBits {
    CapabilitiesSecureBits::NO_SETUID_FIXUP
        | CapabilitiesSecureBits::NO_SETUID_FIXUP_LOCKED
        | CapabilitiesSecureBits::KEEP_CAPS
        | CapabilitiesSecureBits::KEEP_CAPS_LOCKED
}

pub(super) fn harden_android_agentd_from_env() -> Result<()> {
    match env::var(HARDENING_ENV) {
        Err(env::VarError::NotPresent) => return Ok(()),
        Ok(value) if value == "1" => {}
        Ok(_) => bail!("{HARDENING_ENV} must be exactly 1 when present"),
        Err(env::VarError::NotUnicode(_)) => bail!("{HARDENING_ENV} must be valid UTF-8"),
    }
    if unsafe { libc::geteuid() } != 0 {
        bail!("Android agentd capability hardening requires initial effective UID 0");
    }
    harden_current_thread()
}

fn harden_current_thread() -> Result<()> {
    // This must run before the daemon starts any worker or reaper thread.
    // Linux capability sets and the bounding set are per-thread; children then
    // inherit the already-reduced state from this sole startup thread.
    let before = capabilities(None).context("cannot read initial agentd capabilities")?;
    validate_startup_capabilities(before)?;
    let supported = supported_capabilities()?;

    let secure_bits = capabilities_secure_bits().context("cannot read agentd securebits")?;
    if secure_bits.intersects(forbidden_secure_bits()) {
        bail!("agentd inherited unsafe setuid capability-preservation securebits");
    }
    set_capabilities_secure_bits(secure_bits | required_secure_bits())
        .context("cannot lock agentd root/ambient capability regain")?;
    clear_ambient_capability_set().context("cannot clear agentd ambient capabilities")?;

    // CAP_SETPCAP is required only for PR_CAPBSET_DROP. Drop every other
    // supported bounding bit first, then irreversibly drop CAP_SETPCAP itself.
    // The retained effective/permitted set below is sufficient for the current
    // process but can never be regained by a later exec.
    for capability in bounding_drop_order(&supported) {
        if capability_is_in_bounding_set(capability)
            .with_context(|| format!("cannot inspect agentd bounding bit {capability:?}"))?
        {
            remove_capability_from_bounding_set(capability)
                .with_context(|| format!("cannot drop agentd bounding bit {capability:?}"))?;
        }
    }

    let retained = long_lived_capabilities();
    set_capabilities(
        None,
        CapabilitySets {
            effective: retained,
            permitted: retained,
            inheritable: CapabilitySet::empty(),
        },
    )
    .context("cannot reduce agentd effective/permitted capabilities")?;

    verify_hardened_state(&supported)?;
    eprintln!("{ACTIVE_MARKER}");
    Ok(())
}

fn validate_startup_capabilities(observed: CapabilitySets) -> Result<()> {
    let expected = startup_capabilities();
    if observed.effective != expected || observed.permitted != expected {
        bail!(
            "agentd initial effective/permitted capability set differs from the exact reviewed startup set: expected={expected:?} observed_effective={:?} observed_permitted={:?}",
            observed.effective,
            observed.permitted,
        );
    }
    if !expected.contains(observed.inheritable) {
        bail!("agentd initial inheritable capability set contains an unreviewed bit");
    }
    Ok(())
}

fn supported_capabilities() -> Result<Vec<CapabilitySet>> {
    let mut supported = Vec::new();
    for bit in 0..MAX_LINUX_CAPABILITY_BITS {
        let capability = capability_from_bit(bit);
        match capability_is_in_bounding_set(capability) {
            Ok(_) => supported.push(capability),
            Err(Errno::INVAL) => break,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("cannot enumerate Linux capability bit {bit}"));
            }
        }
    }
    if !supported.contains(&CapabilitySet::SYS_CHROOT)
        || !supported.contains(&CapabilitySet::SETPCAP)
    {
        bail!("kernel capability inventory omits required startup capability numbers");
    }
    Ok(supported)
}

fn bounding_drop_order(supported: &[CapabilitySet]) -> Vec<CapabilitySet> {
    let mut order = supported
        .iter()
        .copied()
        .filter(|capability| *capability != CapabilitySet::SETPCAP)
        .collect::<Vec<_>>();
    if supported.contains(&CapabilitySet::SETPCAP) {
        order.push(CapabilitySet::SETPCAP);
    }
    order
}

fn verify_hardened_state(supported: &[CapabilitySet]) -> Result<()> {
    let retained = long_lived_capabilities();
    let observed = capabilities(None).context("cannot verify reduced agentd capabilities")?;
    if observed
        != (CapabilitySets {
            effective: retained,
            permitted: retained,
            inheritable: CapabilitySet::empty(),
        })
    {
        bail!("agentd capability reduction did not reach the exact long-lived set");
    }

    let secure_bits = capabilities_secure_bits().context("cannot verify agentd securebits")?;
    if !secure_bits.contains(required_secure_bits())
        || secure_bits.intersects(forbidden_secure_bits())
    {
        bail!("agentd securebits are not irreversibly hardened");
    }
    for capability in supported {
        if capability_is_in_bounding_set(*capability)
            .with_context(|| format!("cannot verify agentd bounding bit {capability:?}"))?
        {
            bail!("agentd retained capability in the bounding set: {capability:?}");
        }
        if capability_is_in_ambient_set(*capability)
            .with_context(|| format!("cannot verify agentd ambient bit {capability:?}"))?
        {
            bail!("agentd retained capability in the ambient set: {capability:?}");
        }
    }
    Ok(())
}

fn capability_from_bit(bit: u32) -> CapabilitySet {
    CapabilitySet::from_bits_retain(1_u64 << bit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_lived_set_is_exact_and_excludes_startup_only_capabilities() {
        let retained = long_lived_capabilities();
        assert_eq!(retained.bits(), 0x00e1);
        assert_eq!(retained.bits().count_ones(), 4);
        for required in [
            CapabilitySet::CHOWN,
            CapabilitySet::KILL,
            CapabilitySet::SETGID,
            CapabilitySet::SETUID,
        ] {
            assert!(retained.contains(required));
        }
        assert!(!retained.contains(CapabilitySet::FOWNER));
        assert!(!retained.intersects(CapabilitySet::SETPCAP | CapabilitySet::SYS_CHROOT));
    }

    #[test]
    fn startup_set_adds_only_setpcap_and_sys_chroot() {
        assert_eq!(startup_capabilities().bits(), 0x0004_01e1);
        assert_eq!(
            startup_capabilities() - long_lived_capabilities(),
            CapabilitySet::SETPCAP | CapabilitySet::SYS_CHROOT
        );
    }

    #[test]
    fn initial_capability_contract_rejects_missing_or_extra_bits() {
        let expected = startup_capabilities();
        validate_startup_capabilities(CapabilitySets {
            effective: expected,
            permitted: expected,
            inheritable: expected,
        })
        .unwrap();

        let missing = expected - CapabilitySet::SYS_CHROOT;
        assert!(
            validate_startup_capabilities(CapabilitySets {
                effective: missing,
                permitted: expected,
                inheritable: CapabilitySet::empty(),
            })
            .is_err()
        );
        assert!(
            validate_startup_capabilities(CapabilitySets {
                effective: expected | CapabilitySet::NET_ADMIN,
                permitted: expected | CapabilitySet::NET_ADMIN,
                inheritable: CapabilitySet::empty(),
            })
            .is_err()
        );
        assert!(
            validate_startup_capabilities(CapabilitySets {
                effective: expected | CapabilitySet::FOWNER,
                permitted: expected | CapabilitySet::FOWNER,
                inheritable: CapabilitySet::empty(),
            })
            .is_err()
        );
        assert!(
            validate_startup_capabilities(CapabilitySets {
                effective: expected,
                permitted: expected,
                inheritable: CapabilitySet::NET_RAW,
            })
            .is_err()
        );
    }

    #[test]
    fn bounding_drop_order_keeps_setpcap_until_the_final_drop() {
        let supported = (0..=40).map(capability_from_bit).collect::<Vec<_>>();
        let order = bounding_drop_order(&supported);
        assert_eq!(order.len(), supported.len());
        assert_eq!(order.last(), Some(&CapabilitySet::SETPCAP));
        assert_eq!(
            order
                .iter()
                .filter(|capability| **capability == CapabilitySet::SETPCAP)
                .count(),
            1
        );
    }

    #[test]
    fn securebits_forbid_root_and_ambient_capability_regain() {
        let required = required_secure_bits();
        assert!(required.contains(CapabilitiesSecureBits::NO_ROOT));
        assert!(required.contains(CapabilitiesSecureBits::NO_ROOT_LOCKED));
        assert!(required.contains(CapabilitiesSecureBits::NO_CAP_AMBIENT_RAISE));
        assert!(required.contains(CapabilitiesSecureBits::NO_CAP_AMBIENT_RAISE_LOCKED));
        assert!(!required.intersects(forbidden_secure_bits()));
        assert_eq!(
            ACTIVE_MARKER,
            "TRILLIONNIUM_AGENTD_CAPABILITY_HARDENING_V1_ACTIVE"
        );
    }

    #[test]
    #[ignore = "requires an isolated root child with the exact reviewed startup capabilities"]
    fn privileged_linux_kernel_reaches_verified_hardened_state() {
        assert_eq!(
            env::var("TRILLIONNIUM_RUN_PRIVILEGED_CAPABILITY_TEST").as_deref(),
            Ok("1")
        );
        harden_current_thread().unwrap();
    }
}
