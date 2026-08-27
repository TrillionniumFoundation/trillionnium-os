use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::process::Command;

use anyhow::{Context, Result, bail};
use rustix::thread::{CapabilitiesSecureBits, capabilities_secure_bits};
use serde_json::{Value, json};

#[path = "../capability_hardening.rs"]
mod capability_hardening;

const CHILD_FLAG: &str = "--exec-child";
const HARDENING_ENV: &str = "TRILLIONNIUM_ANDROID_AGENTD_CAPABILITY_HARDENING";
const RETAINED_CAPABILITY_MASK: u64 = 0x00e1;

#[derive(Debug, Clone, PartialEq, Eq)]
struct CapabilitySnapshot {
    effective: u64,
    permitted: u64,
    inheritable: u64,
    bounding: u64,
    ambient: u64,
    securebits: u32,
}

fn required_securebits() -> CapabilitiesSecureBits {
    CapabilitiesSecureBits::NO_ROOT
        | CapabilitiesSecureBits::NO_ROOT_LOCKED
        | CapabilitiesSecureBits::NO_CAP_AMBIENT_RAISE
        | CapabilitiesSecureBits::NO_CAP_AMBIENT_RAISE_LOCKED
}

fn forbidden_securebits() -> CapabilitiesSecureBits {
    CapabilitiesSecureBits::NO_SETUID_FIXUP
        | CapabilitiesSecureBits::NO_SETUID_FIXUP_LOCKED
        | CapabilitiesSecureBits::KEEP_CAPS
        | CapabilitiesSecureBits::KEEP_CAPS_LOCKED
}

fn status_fields() -> Result<BTreeMap<String, String>> {
    let contents = fs::read_to_string("/proc/self/status")
        .context("cannot read /proc/self/status for capability conformance")?;
    Ok(contents
        .lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.to_string(), value.trim().to_string()))
        .collect())
}

fn parse_capability_field(fields: &BTreeMap<String, String>, name: &str) -> Result<u64> {
    let value = fields
        .get(name)
        .with_context(|| format!("/proc/self/status omits {name}"))?;
    u64::from_str_radix(value, 16).with_context(|| format!("{name} is not hexadecimal"))
}

fn snapshot() -> Result<CapabilitySnapshot> {
    let fields = status_fields()?;
    Ok(CapabilitySnapshot {
        effective: parse_capability_field(&fields, "CapEff")?,
        permitted: parse_capability_field(&fields, "CapPrm")?,
        inheritable: parse_capability_field(&fields, "CapInh")?,
        bounding: parse_capability_field(&fields, "CapBnd")?,
        ambient: parse_capability_field(&fields, "CapAmb")?,
        securebits: capabilities_secure_bits()
            .context("cannot read PR_GET_SECUREBITS")?
            .bits(),
    })
}

fn snapshot_json(phase: &str, state: &CapabilitySnapshot) -> Value {
    json!({
        "phase": phase,
        "proc_status": {
            "CapEff": format!("{:016x}", state.effective),
            "CapPrm": format!("{:016x}", state.permitted),
            "CapInh": format!("{:016x}", state.inheritable),
            "CapBnd": format!("{:016x}", state.bounding),
            "CapAmb": format!("{:016x}", state.ambient),
        },
        "securebits": {
            "value_hex": format!("{:08x}", state.securebits),
            "no_root": state.securebits & CapabilitiesSecureBits::NO_ROOT.bits() != 0,
            "no_root_locked": state.securebits & CapabilitiesSecureBits::NO_ROOT_LOCKED.bits() != 0,
            "no_cap_ambient_raise": state.securebits & CapabilitiesSecureBits::NO_CAP_AMBIENT_RAISE.bits() != 0,
            "no_cap_ambient_raise_locked": state.securebits & CapabilitiesSecureBits::NO_CAP_AMBIENT_RAISE_LOCKED.bits() != 0,
        }
    })
}

fn validate_securebits(state: &CapabilitySnapshot) -> Result<()> {
    let observed = CapabilitiesSecureBits::from_bits_retain(state.securebits);
    if !observed.contains(required_securebits()) || observed.intersects(forbidden_securebits()) {
        bail!("securebits do not enforce irreversible root/ambient capability non-regain");
    }
    Ok(())
}

fn validate_hardened_parent(state: &CapabilitySnapshot) -> Result<()> {
    if state.effective != RETAINED_CAPABILITY_MASK
        || state.permitted != RETAINED_CAPABILITY_MASK
        || state.inheritable != 0
        || state.bounding != 0
        || state.ambient != 0
    {
        bail!("hardened parent capability sets differ from the reviewed exact state");
    }
    validate_securebits(state)
}

fn validate_exec_child(state: &CapabilitySnapshot) -> Result<()> {
    if state.effective != 0
        || state.permitted != 0
        || state.inheritable != 0
        || state.bounding != 0
        || state.ambient != 0
    {
        bail!("child exec regained a Linux capability");
    }
    validate_securebits(state)
}

fn run_child() -> Result<()> {
    if env::var_os(HARDENING_ENV).is_some() {
        bail!("exec child must not re-run the parent hardening entrypoint");
    }
    let state = snapshot()?;
    validate_exec_child(&state)?;
    println!("{}", snapshot_json("post_exec_child", &state));
    Ok(())
}

fn run_parent() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("capability conformance parent requires effective UID 0");
    }
    capability_hardening::harden_android_agentd_from_env()?;
    let parent = snapshot()?;
    validate_hardened_parent(&parent)?;

    let executable = env::current_exe().context("cannot resolve conformance executable")?;
    let child = Command::new(&executable)
        .arg(CHILD_FLAG)
        .env_remove(HARDENING_ENV)
        .output()
        .context("cannot exec capability conformance child")?;
    if !child.status.success() {
        bail!(
            "capability conformance child failed: {}",
            String::from_utf8_lossy(&child.stderr).trim()
        );
    }
    let child_value: Value = serde_json::from_slice(&child.stdout)
        .context("capability conformance child emitted invalid JSON")?;

    println!(
        "{}",
        json!({
            "schema": "org.trillionnium.agentd-capability-runtime-conformance.v1",
            "status": "PASS_AGENTD_CAPABILITY_NON_REGAIN",
            "parent": snapshot_json("post_hardening_parent", &parent),
            "child": child_value,
            "expected": {
                "parent_effective_permitted_hex": format!("{:016x}", RETAINED_CAPABILITY_MASK),
                "parent_inheritable_bounding_ambient_hex": "0000000000000000",
                "child_all_capability_sets_hex": "0000000000000000",
                "securebits_root_regain_locked": true,
                "securebits_ambient_raise_locked": true,
            }
        })
    );
    Ok(())
}

fn main() -> Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [] => run_parent(),
        [flag] if flag == CHILD_FLAG => run_child(),
        _ => bail!("usage: trillionnium-agentd-capability-conformance [{CHILD_FLAG}]"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAP_FOWNER_MASK: u64 = 1 << 3;

    fn reviewed_parent() -> CapabilitySnapshot {
        CapabilitySnapshot {
            effective: RETAINED_CAPABILITY_MASK,
            permitted: RETAINED_CAPABILITY_MASK,
            inheritable: 0,
            bounding: 0,
            ambient: 0,
            securebits: required_securebits().bits(),
        }
    }

    #[test]
    fn exact_parent_and_exec_child_contracts_are_distinct() {
        let parent = reviewed_parent();
        validate_hardened_parent(&parent).unwrap();
        assert!(validate_exec_child(&parent).is_err());

        let child = CapabilitySnapshot {
            effective: 0,
            permitted: 0,
            inheritable: 0,
            bounding: 0,
            ambient: 0,
            securebits: required_securebits().bits(),
        };
        validate_exec_child(&child).unwrap();
        assert!(validate_hardened_parent(&child).is_err());
    }

    #[test]
    fn cap_fowner_is_not_part_of_the_reviewed_parent_contract() {
        assert_eq!(RETAINED_CAPABILITY_MASK, 0x00e1);
        assert_eq!(RETAINED_CAPABILITY_MASK & CAP_FOWNER_MASK, 0);

        let mut parent = reviewed_parent();
        parent.effective |= CAP_FOWNER_MASK;
        parent.permitted |= CAP_FOWNER_MASK;
        assert!(validate_hardened_parent(&parent).is_err());
    }

    #[test]
    fn any_regained_child_set_or_unlocked_securebit_is_rejected() {
        for field in 0..5 {
            let mut child = CapabilitySnapshot {
                effective: 0,
                permitted: 0,
                inheritable: 0,
                bounding: 0,
                ambient: 0,
                securebits: required_securebits().bits(),
            };
            match field {
                0 => child.effective = 1,
                1 => child.permitted = 1,
                2 => child.inheritable = 1,
                3 => child.bounding = 1,
                _ => child.ambient = 1,
            }
            assert!(validate_exec_child(&child).is_err());
        }
        let mut child = reviewed_parent();
        child.effective = 0;
        child.permitted = 0;
        child.securebits &= !CapabilitiesSecureBits::NO_ROOT_LOCKED.bits();
        assert!(validate_exec_child(&child).is_err());
    }
}
