//! Inert, device-local ADB wire-protocol foundation.
//!
//! This module deliberately contains no socket implementation, adb process
//! launcher, private key, TLS implementation, or product entrypoint. It only
//! defines the fixed self-target, bounded framing, an explicit-timeout
//! transport interface, and a fail-closed client state machine that can be
//! exercised with an in-memory transport.

use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::num::NonZeroU32;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

/// Source-only OS-owned admission/transport boundary layered above the wire
/// state machine below.  Keeping this as a child module makes the distinction
/// between the ADB protocol and the authority boundary explicit: a valid wire
/// frame is not, by itself, an admitted OS operation.
#[path = "adb_transport_boundary.rs"]
pub mod transport_boundary;

pub use transport_boundary::{
    ADB_BROKER_UDS_SCHEMA, ADB_PRODUCTION_TRANSPORT_STATUS, ADB_TRANSPORT_BOUNDARY_SCHEMA,
    AdbAdmissionPolicy, AdbBrokerDispatch, AdbBrokerRequestFrame, AdbBrokerResponseFrame,
    AdbTransport, AdbTransportBoundaryError, AdbTransportBoundaryResult, AdbTransportBroker,
    AdbTransportDisposition, AdbTransportResult, AdmittedAdbRequest, MAX_ADB_BROKER_FRAME_BYTES,
    MAX_ADB_BROKER_LEDGER_ENTRIES, MAX_ADB_BROKER_OUTPUT_BYTES, OsOwnedAdbTransport,
    ProductionAdbTransport, decode_uds_frame, encode_uds_frame,
};

/// Stable source-only contract namespace for the OS-owned Android ADB
/// transport.  This is intentionally distinct from the `rootlinux.exec.*`
/// shell/exec namespace: an ADB request cannot be reinterpreted as a Linux
/// process execution request (or vice versa).
pub const ANDROID_ADB_CONTRACT_SCHEMA: &str = "android.adb.transport.v1";
pub const ANDROID_ADB_CONTRACT_VERSION: u16 = 1;
pub const ROOTLINUX_EXEC_NAMESPACE: &str = "rootlinux.exec.";
pub const ANDROID_ADB_NAMESPACE: &str = "android.adb.";
pub const MAX_ANDROID_ADB_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_ANDROID_ADB_REQUEST_ID_BYTES: usize = 128;
pub const MAX_ANDROID_ADB_BINDING_REF_BYTES: usize = 128;
pub const MAX_ANDROID_ADB_ARG_BYTES: usize = 16 * 1024;
pub const SELF_DEVICE_BINDING_REF: &str = "self";

/// Errors raised while validating the inert typed `android.adb.*` contract.
/// None of these errors imply that a transport, key store, or product policy
/// exists; they only reject malformed source-level values.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AndroidAdbContractError {
    #[error("android.adb field {field} is invalid: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    #[error("android.adb value is invalid: {0}")]
    InvalidValue(String),
    #[error("android.adb model input contains forbidden private key material at {path}")]
    PrivateKeyMaterialForbidden { path: String },
    #[error("android.adb model input exceeds {maximum} bytes")]
    RequestTooLarge { maximum: usize },
    #[error("android.adb model input is not valid JSON: {0}")]
    Json(String),
}

pub type AndroidAdbContractResult<T> = std::result::Result<T, AndroidAdbContractError>;

/// Namespace classification is kept separate from operation decoding so a
/// dispatcher can reject a cross-domain ID before it looks at arguments or
/// opens either transport. This is a source contract only; it does not expose
/// a Root Linux executor here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentTransportDomain {
    RootLinuxExec,
    AndroidAdb,
}

impl AgentTransportDomain {
    pub fn classify(operation_id: &str) -> AndroidAdbContractResult<Self> {
        if operation_id.starts_with(ANDROID_ADB_NAMESPACE) {
            Ok(Self::AndroidAdb)
        } else if operation_id.starts_with(ROOTLINUX_EXEC_NAMESPACE) {
            Ok(Self::RootLinuxExec)
        } else {
            Err(AndroidAdbContractError::InvalidValue(
                "operation id is outside the closed transport namespaces".to_string(),
            ))
        }
    }
}

/// Closed semantic ADB operations exposed by the future direct Agent tool.
/// The operation IDs are versioned and live only in the `android.adb.*`
/// namespace.  There is deliberately no raw command-string or generic
/// `rootlinux.exec` operation here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AndroidAdbOperation {
    #[serde(rename = "android.adb.devices.v1", alias = "devices")]
    Devices,
    #[serde(rename = "android.adb.get_state.v1", alias = "get_state")]
    GetState,
    #[serde(rename = "android.adb.inspect_device.v1", alias = "inspect_device")]
    InspectDevice,
    #[serde(rename = "android.adb.shell.v1", alias = "shell")]
    Shell,
    #[serde(rename = "android.adb.push.v1", alias = "push")]
    Push,
    #[serde(rename = "android.adb.pull.v1", alias = "pull")]
    Pull,
    #[serde(rename = "android.adb.install.v1", alias = "install")]
    Install,
    #[serde(rename = "android.adb.uninstall.v1", alias = "uninstall")]
    Uninstall,
    #[serde(rename = "android.adb.reboot.v1", alias = "reboot")]
    Reboot,
    #[serde(rename = "android.adb.root.v1", alias = "root")]
    Root,
    #[serde(rename = "android.adb.remount.v1", alias = "remount")]
    Remount,
    #[serde(rename = "android.adb.sideload.v1", alias = "sideload")]
    Sideload,
    #[serde(rename = "android.adb.flash.v1", alias = "flash")]
    Flash,
}

impl AndroidAdbOperation {
    pub fn from_operation_id(value: &str) -> AndroidAdbContractResult<Self> {
        let operation = match value {
            "android.adb.devices.v1" | "devices" => Self::Devices,
            "android.adb.get_state.v1" | "get_state" => Self::GetState,
            "android.adb.inspect_device.v1" | "inspect_device" => Self::InspectDevice,
            "android.adb.shell.v1" | "shell" => Self::Shell,
            "android.adb.push.v1" | "push" => Self::Push,
            "android.adb.pull.v1" | "pull" => Self::Pull,
            "android.adb.install.v1" | "install" => Self::Install,
            "android.adb.uninstall.v1" | "uninstall" => Self::Uninstall,
            "android.adb.reboot.v1" | "reboot" => Self::Reboot,
            "android.adb.root.v1" | "root" => Self::Root,
            "android.adb.remount.v1" | "remount" => Self::Remount,
            "android.adb.sideload.v1" | "sideload" => Self::Sideload,
            "android.adb.flash.v1" | "flash" => Self::Flash,
            _ => {
                return Err(AndroidAdbContractError::InvalidValue(
                    "unknown android.adb operation id".to_string(),
                ));
            }
        };
        Ok(operation)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Devices => "android.adb.devices.v1",
            Self::GetState => "android.adb.get_state.v1",
            Self::InspectDevice => "android.adb.inspect_device.v1",
            Self::Shell => "android.adb.shell.v1",
            Self::Push => "android.adb.push.v1",
            Self::Pull => "android.adb.pull.v1",
            Self::Install => "android.adb.install.v1",
            Self::Uninstall => "android.adb.uninstall.v1",
            Self::Reboot => "android.adb.reboot.v1",
            Self::Root => "android.adb.root.v1",
            Self::Remount => "android.adb.remount.v1",
            Self::Sideload => "android.adb.sideload.v1",
            Self::Flash => "android.adb.flash.v1",
        }
    }

    /// Alias useful at call sites that deal in operation IDs rather than
    /// enum values.
    #[must_use]
    pub const fn operation_id(self) -> &'static str {
        self.as_str()
    }

    #[must_use]
    pub const fn minimum_tier(self) -> AndroidAdbTier {
        match self {
            Self::Devices | Self::GetState | Self::InspectDevice => AndroidAdbTier::ReadOnly,
            Self::Shell | Self::Push | Self::Pull => AndroidAdbTier::User,
            Self::Install | Self::Uninstall | Self::Reboot => AndroidAdbTier::Developer,
            Self::Root | Self::Remount | Self::Sideload | Self::Flash => AndroidAdbTier::Recovery,
        }
    }

    #[must_use]
    pub const fn is_destructive(self) -> bool {
        matches!(
            self,
            Self::Install
                | Self::Uninstall
                | Self::Reboot
                | Self::Root
                | Self::Remount
                | Self::Sideload
                | Self::Flash
        )
    }
}

impl TryFrom<&str> for AndroidAdbOperation {
    type Error = AndroidAdbContractError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_operation_id(value)
    }
}

/// Graded OS policy levels for ADB.  A higher level is not an ambient grant:
/// it is a bounded policy input that must still be selected by the OS for a
/// particular authenticated turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AndroidAdbTier {
    ReadOnly,
    User,
    Developer,
    Recovery,
}

impl AndroidAdbTier {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::User => "user",
            Self::Developer => "developer",
            Self::Recovery => "recovery",
        }
    }

    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::ReadOnly => 0,
            Self::User => 1,
            Self::Developer => 2,
            Self::Recovery => 3,
        }
    }

    #[must_use]
    pub const fn allows(self, operation: AndroidAdbOperation) -> bool {
        self.rank() >= operation.minimum_tier().rank()
    }

    #[must_use]
    pub const fn is_at_least(self, required: Self) -> bool {
        self.rank() >= required.rank()
    }
}

/// More descriptive aliases retained for callers that use the policy rather
/// than transport terminology.
pub type AndroidAdbPermissionTier = AndroidAdbTier;
pub type AdbPermissionTier = AndroidAdbTier;

/// A bounded permission grant selected by the OS.  The model can request an
/// operation but cannot mint this value or extend its expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AndroidAdbPermissionGrant {
    pub tier: AndroidAdbTier,
    pub expires_at_boot: Option<u64>,
    pub user_confirmation_required: bool,
}

impl AndroidAdbPermissionGrant {
    pub fn validate(&self) -> AndroidAdbContractResult<()> {
        if self.expires_at_boot == Some(0) {
            return Err(AndroidAdbContractError::InvalidField {
                field: "expires_at_boot",
                reason: "must be non-zero when present",
            });
        }
        Ok(())
    }

    #[must_use]
    pub const fn allows(self, operation: AndroidAdbOperation, boot: Option<u64>) -> bool {
        if let Some(expires) = self.expires_at_boot {
            let Some(current_boot) = boot else {
                return false;
            };
            if current_boot > expires {
                return false;
            }
        }
        self.tier.allows(operation)
    }
}

/// OS-authored identity binding for one Android device.  All identity fields
/// are digests or opaque binding IDs; serials, hostnames, ports, and transport
/// selectors are intentionally not representable in this model-facing type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceBinding {
    pub binding_id: String,
    pub device_identity_sha256: String,
    pub build_fingerprint_sha256: String,
    pub avb_public_key_sha256: String,
    pub binding_generation: u64,
    pub key_generation: u64,
}

impl DeviceBinding {
    pub fn new<B, D, F, A>(
        binding_id: B,
        device_identity_sha256: D,
        build_fingerprint_sha256: F,
        avb_public_key_sha256: A,
        binding_generation: u64,
        key_generation: u64,
    ) -> AndroidAdbContractResult<Self>
    where
        B: Into<String>,
        D: Into<String>,
        F: Into<String>,
        A: Into<String>,
    {
        let binding = Self {
            binding_id: binding_id.into(),
            device_identity_sha256: device_identity_sha256.into(),
            build_fingerprint_sha256: build_fingerprint_sha256.into(),
            avb_public_key_sha256: avb_public_key_sha256.into(),
            binding_generation,
            key_generation,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn validate(&self) -> AndroidAdbContractResult<()> {
        validate_opaque_id(
            &self.binding_id,
            "binding_id",
            MAX_ANDROID_ADB_BINDING_REF_BYTES,
        )?;
        validate_sha256_hex(&self.device_identity_sha256, "device_identity_sha256")?;
        validate_sha256_hex(&self.build_fingerprint_sha256, "build_fingerprint_sha256")?;
        validate_sha256_hex(&self.avb_public_key_sha256, "avb_public_key_sha256")?;
        if self.binding_generation == 0 {
            return Err(AndroidAdbContractError::InvalidField {
                field: "binding_generation",
                reason: "must be non-zero",
            });
        }
        if self.key_generation == 0 {
            return Err(AndroidAdbContractError::InvalidField {
                field: "key_generation",
                reason: "must be non-zero",
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn binding_ref(&self) -> &str {
        &self.binding_id
    }

    pub fn validate_key_generation(
        &self,
        policy: &KeyRotationPolicy,
        boot: u64,
    ) -> AndroidAdbContractResult<()> {
        self.validate()?;
        policy.validate()?;
        if policy.accepts_generation(self.key_generation, boot) {
            Ok(())
        } else {
            Err(AndroidAdbContractError::InvalidValue(
                "device binding references a stale or revoked ADB key generation".to_string(),
            ))
        }
    }
}

pub type AndroidAdbDeviceBinding = DeviceBinding;

/// The only key material shape the source contract can carry.  It contains an
/// OS-held handle and a public-key measurement, never private key bytes.  This
/// type is OS-side metadata and is deliberately absent from
/// [`AdbTransportRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "custody", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdbKeyCustody {
    OsOwned {
        handle_id: String,
        public_key_sha256: String,
        generation: u64,
    },
    ExternalSigner {
        signer_id: String,
        public_key_sha256: String,
        generation: u64,
    },
    Unavailable,
}

impl AdbKeyCustody {
    pub fn validate(&self) -> AndroidAdbContractResult<()> {
        match self {
            Self::OsOwned {
                handle_id,
                public_key_sha256,
                generation,
            } => {
                validate_opaque_id(handle_id, "handle_id", MAX_ANDROID_ADB_BINDING_REF_BYTES)?;
                validate_sha256_hex(public_key_sha256, "public_key_sha256")?;
                validate_nonzero_generation(*generation, "generation")
            }
            Self::ExternalSigner {
                signer_id,
                public_key_sha256,
                generation,
            } => {
                validate_opaque_id(signer_id, "signer_id", MAX_ANDROID_ADB_BINDING_REF_BYTES)?;
                validate_sha256_hex(public_key_sha256, "public_key_sha256")?;
                validate_nonzero_generation(*generation, "generation")
            }
            Self::Unavailable => Ok(()),
        }
    }

    #[must_use]
    pub const fn generation(&self) -> Option<u64> {
        match self {
            Self::OsOwned { generation, .. } | Self::ExternalSigner { generation, .. } => {
                Some(*generation)
            }
            Self::Unavailable => None,
        }
    }

    /// There is no variant that can carry a permanent private key.  Keeping
    /// this predicate explicit makes the invariant easy to audit at callers.
    #[must_use]
    pub const fn is_model_safe(&self) -> bool {
        true
    }
}

/// Monotonic key-generation and overlap policy.  Rotation may retain the
/// previous generation only until a bounded boot counter; rollback to an older
/// generation is never accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRotationPolicy {
    pub current_generation: u64,
    pub previous_generation: Option<u64>,
    pub overlap_until_boot: Option<u64>,
    pub custody: AdbKeyCustody,
}

impl KeyRotationPolicy {
    pub fn new(current_generation: u64, custody: AdbKeyCustody) -> AndroidAdbContractResult<Self> {
        let policy = Self {
            current_generation,
            previous_generation: None,
            overlap_until_boot: None,
            custody,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> AndroidAdbContractResult<()> {
        validate_nonzero_generation(self.current_generation, "current_generation")?;
        if let Some(previous) = self.previous_generation {
            validate_nonzero_generation(previous, "previous_generation")?;
            if previous >= self.current_generation {
                return Err(AndroidAdbContractError::InvalidField {
                    field: "previous_generation",
                    reason: "must be older than current_generation",
                });
            }
            if self.overlap_until_boot.is_none() {
                return Err(AndroidAdbContractError::InvalidField {
                    field: "overlap_until_boot",
                    reason: "required while a previous generation is retained",
                });
            }
            if self.overlap_until_boot == Some(0) {
                return Err(AndroidAdbContractError::InvalidField {
                    field: "overlap_until_boot",
                    reason: "must be non-zero",
                });
            }
        } else if self.overlap_until_boot.is_some() {
            return Err(AndroidAdbContractError::InvalidField {
                field: "overlap_until_boot",
                reason: "cannot be set without previous_generation",
            });
        }
        self.custody.validate()?;
        if let Some(custody_generation) = self.custody.generation()
            && custody_generation != self.current_generation
        {
            return Err(AndroidAdbContractError::InvalidField {
                field: "custody.generation",
                reason: "custody generation must equal current_generation",
            });
        }
        Ok(())
    }

    #[must_use]
    pub const fn accepts_generation(&self, generation: u64, boot: u64) -> bool {
        if generation == self.current_generation {
            return true;
        }
        matches!((self.previous_generation, self.overlap_until_boot), (Some(previous), Some(until)) if generation == previous && boot <= until)
    }

    pub fn rotate(
        &self,
        next_generation: u64,
        overlap_until_boot: Option<u64>,
        custody: AdbKeyCustody,
    ) -> AndroidAdbContractResult<Self> {
        self.validate()?;
        if next_generation <= self.current_generation {
            return Err(AndroidAdbContractError::InvalidField {
                field: "next_generation",
                reason: "rotation must strictly increase the generation",
            });
        }
        let next = Self {
            current_generation: next_generation,
            previous_generation: Some(self.current_generation),
            overlap_until_boot,
            custody,
        };
        next.validate()?;
        Ok(next)
    }
}

pub type AndroidAdbKeyRotationPolicy = KeyRotationPolicy;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AndroidAdbRebootTarget {
    Bootloader,
    Recovery,
    Sideload,
    SideloadAutoReboot,
}

/// Closed semantic arguments.  No command string, executable path, serial,
/// host, port, file descriptor, or key bytes can be supplied by the model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AndroidAdbArguments {
    Empty,
    Shell {
        argv: Vec<String>,
    },
    Push {
        local: String,
        remote: String,
    },
    Pull {
        remote: String,
        local: String,
    },
    Install {
        apk: String,
        replace: bool,
    },
    Uninstall {
        package: String,
    },
    Reboot {
        target: Option<AndroidAdbRebootTarget>,
    },
}

impl AndroidAdbArguments {
    fn validate(&self) -> AndroidAdbContractResult<()> {
        match self {
            Self::Empty => Ok(()),
            Self::Shell { argv } => {
                if argv.is_empty() || argv.len() > 256 {
                    return Err(AndroidAdbContractError::InvalidField {
                        field: "arguments.argv",
                        reason: "must contain 1..=256 arguments",
                    });
                }
                if argv.iter().any(|arg| {
                    arg.is_empty()
                        || arg.len() > MAX_ANDROID_ADB_ARG_BYTES
                        || arg.chars().any(char::is_control)
                }) {
                    return Err(AndroidAdbContractError::InvalidField {
                        field: "arguments.argv",
                        reason: "arguments must be bounded, non-empty, and free of controls",
                    });
                }
                Ok(())
            }
            Self::Push { local, remote } => {
                validate_path(local, "arguments.local")?;
                validate_path(remote, "arguments.remote")
            }
            Self::Pull { remote, local } => {
                validate_path(remote, "arguments.remote")?;
                validate_path(local, "arguments.local")
            }
            Self::Install { apk, .. } => {
                validate_path(apk, "arguments.apk")?;
                if !apk.ends_with(".apk") {
                    return Err(AndroidAdbContractError::InvalidField {
                        field: "arguments.apk",
                        reason: "must end in .apk",
                    });
                }
                Ok(())
            }
            Self::Uninstall { package } => {
                if !valid_package_name(package) {
                    return Err(AndroidAdbContractError::InvalidField {
                        field: "arguments.package",
                        reason: "invalid Android package name",
                    });
                }
                Ok(())
            }
            Self::Reboot { .. } => Ok(()),
        }
    }
}

/// Model-facing typed request.  This is intentionally a separate shape from
/// [`DeviceBinding`] and [`KeyRotationPolicy`], which are OS-authored custody
/// records.  In particular there is no field through which a model/provider
/// can pass an ADB private key or ask the transport to select a host/serial.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdbTransportRequest {
    pub protocol_version: u16,
    pub request_id: String,
    pub operation: AndroidAdbOperation,
    pub device_binding: String,
    pub arguments: AndroidAdbArguments,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAdbTransportRequest {
    protocol_version: u16,
    request_id: String,
    operation: AndroidAdbOperation,
    device_binding: String,
    arguments: AndroidAdbArguments,
}

impl<'de> Deserialize<'de> for AdbTransportRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserialize through a value first so the same recursive private-key
        // guard applies to direct serde callers, not only to
        // `parse_android_adb_model_request`.
        let value = serde_json::Value::deserialize(deserializer)?;
        reject_private_key_material(&value, "$".to_string())
            .map_err(<D::Error as serde::de::Error>::custom)?;
        let raw: RawAdbTransportRequest =
            serde_json::from_value(value).map_err(<D::Error as serde::de::Error>::custom)?;
        let request = Self {
            protocol_version: raw.protocol_version,
            request_id: raw.request_id,
            operation: raw.operation,
            device_binding: raw.device_binding,
            arguments: raw.arguments,
        };
        request
            .validate()
            .map_err(<D::Error as serde::de::Error>::custom)?;
        Ok(request)
    }
}

impl AdbTransportRequest {
    pub fn new<R, B>(
        request_id: R,
        operation: AndroidAdbOperation,
        device_binding: B,
        arguments: AndroidAdbArguments,
    ) -> AndroidAdbContractResult<Self>
    where
        R: Into<String>,
        B: Into<String>,
    {
        let request = Self {
            protocol_version: ANDROID_ADB_CONTRACT_VERSION,
            request_id: request_id.into(),
            operation,
            device_binding: device_binding.into(),
            arguments,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> AndroidAdbContractResult<()> {
        if self.protocol_version != ANDROID_ADB_CONTRACT_VERSION {
            return Err(AndroidAdbContractError::InvalidField {
                field: "protocol_version",
                reason: "unsupported android.adb contract version",
            });
        }
        validate_opaque_id(
            &self.request_id,
            "request_id",
            MAX_ANDROID_ADB_REQUEST_ID_BYTES,
        )?;
        if self.device_binding != SELF_DEVICE_BINDING_REF {
            validate_opaque_id(
                &self.device_binding,
                "device_binding",
                MAX_ANDROID_ADB_BINDING_REF_BYTES,
            )?;
        }
        self.arguments.validate()?;
        let expected_kind = match self.operation {
            AndroidAdbOperation::Shell => 1,
            AndroidAdbOperation::Push => 2,
            AndroidAdbOperation::Pull => 3,
            AndroidAdbOperation::Install => 4,
            AndroidAdbOperation::Uninstall => 5,
            AndroidAdbOperation::Reboot => 6,
            AndroidAdbOperation::Devices
            | AndroidAdbOperation::GetState
            | AndroidAdbOperation::InspectDevice
            | AndroidAdbOperation::Root
            | AndroidAdbOperation::Remount
            | AndroidAdbOperation::Sideload
            | AndroidAdbOperation::Flash => 0,
        };
        let actual_kind = match self.arguments {
            AndroidAdbArguments::Empty => 0,
            AndroidAdbArguments::Shell { .. } => 1,
            AndroidAdbArguments::Push { .. } => 2,
            AndroidAdbArguments::Pull { .. } => 3,
            AndroidAdbArguments::Install { .. } => 4,
            AndroidAdbArguments::Uninstall { .. } => 5,
            AndroidAdbArguments::Reboot { .. } => 6,
        };
        if expected_kind != actual_kind {
            return Err(AndroidAdbContractError::InvalidValue(
                "arguments do not match the typed android.adb operation".to_string(),
            ));
        }
        Ok(())
    }

    /// Bind a model-authored semantic request to the OS-selected device,
    /// current key-generation policy, and expiring permission tier.  This is
    /// still only a source check: it does not mint a capability or perform I/O.
    pub fn validate_admission(
        &self,
        binding: &DeviceBinding,
        rotation: &KeyRotationPolicy,
        grant: AndroidAdbPermissionGrant,
        boot: u64,
    ) -> AndroidAdbContractResult<()> {
        self.validate()?;
        binding.validate_key_generation(rotation, boot)?;
        grant.validate()?;
        if self.device_binding != SELF_DEVICE_BINDING_REF
            && self.device_binding != binding.binding_id
        {
            return Err(AndroidAdbContractError::InvalidValue(
                "request device binding does not match the OS-selected device".to_string(),
            ));
        }
        if !grant.allows(self.operation, Some(boot)) {
            return Err(AndroidAdbContractError::InvalidValue(
                "permission tier or grant expiry does not admit the operation".to_string(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub const fn operation_id(&self) -> &'static str {
        self.operation.as_str()
    }
}

pub type AndroidAdbTransportRequest = AdbTransportRequest;
pub type AndroidAdbModelRequest = AdbTransportRequest;

/// Parse the model-facing request boundary.  The raw JSON is inspected before
/// deserialization so private-key material is rejected even if it is nested in
/// an unknown object.  This is source-only validation; it does not contact an
/// adb daemon or unlock any key custody.
pub fn parse_android_adb_model_request(
    bytes: &[u8],
) -> AndroidAdbContractResult<AdbTransportRequest> {
    if bytes.len() > MAX_ANDROID_ADB_REQUEST_BYTES {
        return Err(AndroidAdbContractError::RequestTooLarge {
            maximum: MAX_ANDROID_ADB_REQUEST_BYTES,
        });
    }
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| AndroidAdbContractError::Json(error.to_string()))?;
    reject_private_key_material(&value, "$".to_string())?;
    let request: AdbTransportRequest = serde_json::from_value(value)
        .map_err(|error| AndroidAdbContractError::Json(error.to_string()))?;
    request.validate()?;
    Ok(request)
}

pub fn parse_adb_transport_request(bytes: &[u8]) -> AndroidAdbContractResult<AdbTransportRequest> {
    parse_android_adb_model_request(bytes)
}

fn reject_private_key_material(
    value: &serde_json::Value,
    path: String,
) -> AndroidAdbContractResult<()> {
    match value {
        serde_json::Value::Object(fields) => {
            for (key, child) in fields {
                let normalized = key.to_ascii_lowercase().replace('-', "_");
                if normalized.contains("private_key")
                    || normalized == "private"
                    || normalized == "privatekey"
                    || normalized == "adbkey"
                    || normalized == "adb_private_key"
                    || normalized.contains("key_material")
                    || normalized == "keymaterial"
                    || normalized.contains("secret_key")
                    || normalized == "secretkey"
                    || normalized == "signing_key"
                    || normalized == "signingkey"
                    || normalized == "key"
                {
                    return Err(AndroidAdbContractError::PrivateKeyMaterialForbidden {
                        path: format!("{path}.{key}"),
                    });
                }
                reject_private_key_material(child, format!("{path}.{key}"))?;
            }
        }
        serde_json::Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                reject_private_key_material(child, format!("{path}[{index}]"))?;
            }
        }
        serde_json::Value::String(text) => {
            let uppercase = text.to_ascii_uppercase();
            if uppercase.contains("BEGIN PRIVATE KEY")
                || uppercase.contains("BEGIN OPENSSH PRIVATE KEY")
                || uppercase.contains("ADBKEY")
            {
                return Err(AndroidAdbContractError::PrivateKeyMaterialForbidden { path });
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_nonzero_generation(value: u64, field: &'static str) -> AndroidAdbContractResult<()> {
    if value == 0 {
        Err(AndroidAdbContractError::InvalidField {
            field,
            reason: "must be non-zero",
        })
    } else {
        Ok(())
    }
}

fn validate_opaque_id(
    value: &str,
    field: &'static str,
    maximum: usize,
) -> AndroidAdbContractResult<()> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        return Err(AndroidAdbContractError::InvalidField {
            field,
            reason: "must be a bounded opaque identifier",
        });
    }
    Ok(())
}

fn validate_sha256_hex(value: &str, field: &'static str) -> AndroidAdbContractResult<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AndroidAdbContractError::InvalidField {
            field,
            reason: "must be exactly 64 hexadecimal characters",
        });
    }
    Ok(())
}

fn validate_path(value: &str, field: &'static str) -> AndroidAdbContractResult<()> {
    if value.is_empty()
        || value.len() > MAX_ANDROID_ADB_ARG_BYTES
        || value.starts_with('-')
        || value.chars().any(char::is_control)
        || !value.starts_with('/')
        || value.split('/').any(|part| part == ".." || part == ".")
    {
        return Err(AndroidAdbContractError::InvalidField {
            field,
            reason: "must be a normalized absolute non-option path",
        });
    }
    Ok(())
}

fn valid_package_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value.split('.').all(|part| {
            !part.is_empty()
                && part.bytes().enumerate().all(|(index, byte)| {
                    byte.is_ascii_alphanumeric() || (index > 0 && byte == b'_')
                })
                && part.as_bytes()[0].is_ascii_alphanumeric()
        })
}

pub const WIRE_HEADER_BYTES: usize = 24;
pub const MAX_WIRE_PAYLOAD_BYTES: usize = 1024 * 1024;
pub const MAX_WIRE_FRAME_BYTES: usize = WIRE_HEADER_BYTES + MAX_WIRE_PAYLOAD_BYTES;
pub const MAX_BANNER_BYTES: usize = 4096;
pub const MAX_SERVICE_BYTES: usize = 4096;
pub const AUTH_TOKEN_BYTES: usize = 20;
pub const AUTH_SIGNATURE_BYTES: usize = 256;
pub const MAX_AUTH_CHALLENGES: usize = 4;
pub const CHECKSUMMED_PROTOCOL_VERSION: u32 = 0x0100_0000;
pub const CHECKSUM_SKIP_PROTOCOL_VERSION: u32 = 0x0100_0001;
pub const CLIENT_ADVERTISED_PROTOCOL_VERSION: AdbProtocolVersion = AdbProtocolVersion::Checksummed;
pub const HOST_MAX_DATA: u32 = 64 * 1024;
pub const FIXED_SELF_ADBD_PORT: u16 = 5555;
pub const MAX_OPERATION_TIMEOUT_MS: u32 = 30_000;

const FIXED_HOST_BANNER: &[u8] = b"host::trillionnium-self-adbd-foundation=1;";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AdbWireError {
    #[error("ADB wire header is malformed: {0}")]
    MalformedHeader(&'static str),
    #[error("unknown ADB wire command 0x{0:08x}")]
    UnknownCommand(u32),
    #[error("ADB wire payload length {length} exceeds bound {maximum}")]
    PayloadTooLarge { length: usize, maximum: usize },
    #[error("ADB wire frame is malformed: {0}")]
    MalformedFrame(&'static str),
    #[error("unsupported ADB protocol version 0x{advertised:08x}")]
    UnsupportedProtocolVersion { advertised: u32 },
    #[error("ADB self-target selector is invalid: {0}")]
    InvalidTarget(&'static str),
    #[error("ADB wire timeout is invalid: {0}")]
    InvalidTimeout(&'static str),
    #[error("ADB wire command {command} is not valid while session is {state}")]
    UnexpectedCommand {
        state: &'static str,
        command: WireCommand,
    },
    #[error("ADB wire stream identifier mismatch")]
    StreamIdMismatch,
    #[error("ADB authentication challenge replay detected")]
    AuthenticationReplay,
    #[error("ADB authentication challenge limit exceeded")]
    AuthenticationLimitExceeded,
    #[error("ADB wire session is already closed")]
    SessionClosed,
    #[error("ADB wire transport failed: {0}")]
    Transport(&'static str),
}

pub type WireResult<T> = std::result::Result<T, AdbWireError>;

/// AOSP's two currently defined CNXN protocol versions.
///
/// The client intentionally advertises [`Self::Checksummed`]. A modern peer
/// may advertise [`Self::ChecksumSkip`], but the negotiated version remains
/// the lower client version, so every frame in this foundation still requires
/// the original ADB checksum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u32)]
pub enum AdbProtocolVersion {
    Checksummed = CHECKSUMMED_PROTOCOL_VERSION,
    ChecksumSkip = CHECKSUM_SKIP_PROTOCOL_VERSION,
}

impl AdbProtocolVersion {
    pub fn from_peer_advertisement(advertised: u32) -> WireResult<Self> {
        match advertised {
            CHECKSUMMED_PROTOCOL_VERSION => Ok(Self::Checksummed),
            CHECKSUM_SKIP_PROTOCOL_VERSION => Ok(Self::ChecksumSkip),
            advertised => Err(AdbWireError::UnsupportedProtocolVersion { advertised }),
        }
    }

    #[must_use]
    pub const fn as_raw(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub fn negotiate_with_client(self) -> Self {
        Self::from_peer_advertisement(
            self.as_raw()
                .min(CLIENT_ADVERTISED_PROTOCOL_VERSION.as_raw()),
        )
        .expect("minimum of supported ADB protocol versions remains supported")
    }
}

/// The complete set of device services that this inert client can open.
///
/// No string constructor exists. In particular, adbd control services such as
/// `root:` and `remount:` and all unknown service names are unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SelfAdbdService {
    ShellV2Raw,
    Sync,
}

impl SelfAdbdService {
    const ALL: [Self; 2] = [Self::ShellV2Raw, Self::Sync];

    const fn wire_payload(self) -> &'static [u8] {
        match self {
            Self::ShellV2Raw => b"shell,v2,raw:\0",
            Self::Sync => b"sync:\0",
        }
    }

    fn accepts_wire_payload(payload: &[u8]) -> bool {
        Self::ALL
            .iter()
            .any(|service| payload == service.wire_payload())
    }
}

/// The only endpoint this foundation can express.
///
/// The fields are private and there is no arbitrary constructor. Product code
/// cannot turn a request-provided host, port, or serial into another target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SelfAdbdEndpoint {
    address: SocketAddrV4,
}

impl SelfAdbdEndpoint {
    #[must_use]
    pub const fn fixed() -> Self {
        Self {
            address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, FIXED_SELF_ADBD_PORT),
        }
    }

    #[must_use]
    pub const fn socket_addr(self) -> SocketAddrV4 {
        self.address
    }

    /// Validates an untrusted selector without resolving DNS. Any serial,
    /// hostname spelling, alternate loopback address, or alternate port is
    /// rejected even if it could eventually reach the same machine.
    pub fn validate_untrusted(host: &str, port: u16, serial: Option<&str>) -> WireResult<Self> {
        if serial.is_some() {
            return Err(AdbWireError::InvalidTarget(
                "serial selection is forbidden for the self-target transport",
            ));
        }
        if host.as_bytes() != b"127.0.0.1" || port != FIXED_SELF_ADBD_PORT {
            return Err(AdbWireError::InvalidTarget(
                "target must be exactly 127.0.0.1:5555",
            ));
        }
        Ok(Self::fixed())
    }
}

/// A non-zero, compile-time bounded timeout required by every future transport
/// operation. Raw `Duration` values are intentionally not accepted by the
/// transport trait.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct StrictTimeout {
    milliseconds: NonZeroU32,
}

impl StrictTimeout {
    pub fn from_millis(milliseconds: u32) -> WireResult<Self> {
        let milliseconds = NonZeroU32::new(milliseconds)
            .ok_or(AdbWireError::InvalidTimeout("timeout must be non-zero"))?;
        if milliseconds.get() > MAX_OPERATION_TIMEOUT_MS {
            return Err(AdbWireError::InvalidTimeout(
                "timeout exceeds the per-operation maximum",
            ));
        }
        Ok(Self { milliseconds })
    }

    #[must_use]
    pub const fn as_millis(self) -> u32 {
        self.milliseconds.get()
    }

    #[must_use]
    pub fn as_duration(self) -> Duration {
        Duration::from_millis(u64::from(self.as_millis()))
    }
}

/// No implementation is provided here. A future debug-only implementation
/// must make the fixed endpoint and a bounded timeout explicit for every
/// blocking operation.
pub trait BoundedWireTransport {
    fn connect(&mut self, endpoint: SelfAdbdEndpoint, timeout: StrictTimeout) -> WireResult<()>;
    fn write_frame(&mut self, frame: &[u8], timeout: StrictTimeout) -> WireResult<()>;
    fn read_frame(&mut self, maximum_bytes: usize, timeout: StrictTimeout) -> WireResult<Vec<u8>>;
    fn shutdown(&mut self, timeout: StrictTimeout) -> WireResult<()>;
}

pub fn transport_write<T: BoundedWireTransport>(
    transport: &mut T,
    frame: &WireFrame,
    timeout: StrictTimeout,
) -> WireResult<()> {
    transport.write_frame(&frame.encode(), timeout)
}

pub fn transport_read<T: BoundedWireTransport>(
    transport: &mut T,
    timeout: StrictTimeout,
) -> WireResult<WireFrame> {
    let encoded = transport.read_frame(MAX_WIRE_FRAME_BYTES, timeout)?;
    if encoded.len() > MAX_WIRE_FRAME_BYTES {
        return Err(AdbWireError::PayloadTooLarge {
            length: encoded.len().saturating_sub(WIRE_HEADER_BYTES),
            maximum: MAX_WIRE_PAYLOAD_BYTES,
        });
    }
    WireFrame::decode(&encoded)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum WireCommand {
    Cnxn = u32::from_le_bytes(*b"CNXN"),
    Auth = u32::from_le_bytes(*b"AUTH"),
    Open = u32::from_le_bytes(*b"OPEN"),
    Okay = u32::from_le_bytes(*b"OKAY"),
    Wrte = u32::from_le_bytes(*b"WRTE"),
    Clse = u32::from_le_bytes(*b"CLSE"),
}

impl WireCommand {
    pub fn from_raw(raw: u32) -> WireResult<Self> {
        match raw {
            value if value == Self::Cnxn as u32 => Ok(Self::Cnxn),
            value if value == Self::Auth as u32 => Ok(Self::Auth),
            value if value == Self::Open as u32 => Ok(Self::Open),
            value if value == Self::Okay as u32 => Ok(Self::Okay),
            value if value == Self::Wrte as u32 => Ok(Self::Wrte),
            value if value == Self::Clse as u32 => Ok(Self::Clse),
            value => Err(AdbWireError::UnknownCommand(value)),
        }
    }
}

impl fmt::Display for WireCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Cnxn => "CNXN",
            Self::Auth => "AUTH",
            Self::Open => "OPEN",
            Self::Okay => "OKAY",
            Self::Wrte => "WRTE",
            Self::Clse => "CLSE",
        };
        formatter.write_str(name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AuthKind {
    Token = 1,
    Signature = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireHeader {
    command: WireCommand,
    arg0: u32,
    arg1: u32,
    data_length: u32,
    data_checksum: u32,
}

impl WireHeader {
    #[must_use]
    pub const fn command(self) -> WireCommand {
        self.command
    }

    #[must_use]
    pub const fn arg0(self) -> u32 {
        self.arg0
    }

    #[must_use]
    pub const fn arg1(self) -> u32 {
        self.arg1
    }

    #[must_use]
    pub const fn data_length(self) -> u32 {
        self.data_length
    }

    #[must_use]
    pub const fn data_checksum(self) -> u32 {
        self.data_checksum
    }

    fn encode(self) -> [u8; WIRE_HEADER_BYTES] {
        let mut encoded = [0_u8; WIRE_HEADER_BYTES];
        let command = self.command as u32;
        encoded[0..4].copy_from_slice(&command.to_le_bytes());
        encoded[4..8].copy_from_slice(&self.arg0.to_le_bytes());
        encoded[8..12].copy_from_slice(&self.arg1.to_le_bytes());
        encoded[12..16].copy_from_slice(&self.data_length.to_le_bytes());
        encoded[16..20].copy_from_slice(&self.data_checksum.to_le_bytes());
        encoded[20..24].copy_from_slice(&(command ^ u32::MAX).to_le_bytes());
        encoded
    }

    fn decode(encoded: &[u8]) -> WireResult<Self> {
        if encoded.len() != WIRE_HEADER_BYTES {
            return Err(AdbWireError::MalformedHeader(
                "header must contain exactly 24 bytes",
            ));
        }
        let command_raw = read_u32(encoded, 0);
        let magic = read_u32(encoded, 20);
        if magic != command_raw ^ u32::MAX {
            return Err(AdbWireError::MalformedHeader("command magic mismatch"));
        }
        let command = WireCommand::from_raw(command_raw)?;
        let data_length = read_u32(encoded, 12);
        if data_length as usize > MAX_WIRE_PAYLOAD_BYTES {
            return Err(AdbWireError::PayloadTooLarge {
                length: data_length as usize,
                maximum: MAX_WIRE_PAYLOAD_BYTES,
            });
        }
        Ok(Self {
            command,
            arg0: read_u32(encoded, 4),
            arg1: read_u32(encoded, 8),
            data_length,
            data_checksum: read_u32(encoded, 16),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireFrame {
    header: WireHeader,
    payload: Vec<u8>,
}

impl WireFrame {
    pub fn new(command: WireCommand, arg0: u32, arg1: u32, payload: Vec<u8>) -> WireResult<Self> {
        if payload.len() > MAX_WIRE_PAYLOAD_BYTES {
            return Err(AdbWireError::PayloadTooLarge {
                length: payload.len(),
                maximum: MAX_WIRE_PAYLOAD_BYTES,
            });
        }
        let frame = Self {
            header: WireHeader {
                command,
                arg0,
                arg1,
                data_length: payload.len() as u32,
                data_checksum: adb_checksum(&payload),
            },
            payload,
        };
        frame.validate_semantics()?;
        Ok(frame)
    }

    pub fn decode(encoded: &[u8]) -> WireResult<Self> {
        if encoded.len() < WIRE_HEADER_BYTES {
            return Err(AdbWireError::MalformedHeader(
                "frame is shorter than the 24-byte header",
            ));
        }
        if encoded.len() > MAX_WIRE_FRAME_BYTES {
            return Err(AdbWireError::PayloadTooLarge {
                length: encoded.len() - WIRE_HEADER_BYTES,
                maximum: MAX_WIRE_PAYLOAD_BYTES,
            });
        }
        let header = WireHeader::decode(&encoded[..WIRE_HEADER_BYTES])?;
        let expected_length = WIRE_HEADER_BYTES
            .checked_add(header.data_length as usize)
            .ok_or(AdbWireError::MalformedHeader("frame length overflow"))?;
        if encoded.len() != expected_length {
            return Err(AdbWireError::MalformedFrame(
                "payload length does not match header",
            ));
        }
        let payload = encoded[WIRE_HEADER_BYTES..].to_vec();
        if adb_checksum(&payload) != header.data_checksum {
            return Err(AdbWireError::MalformedFrame("payload checksum mismatch"));
        }
        let frame = Self { header, payload };
        frame.validate_semantics()?;
        Ok(frame)
    }

    #[must_use]
    pub const fn header(&self) -> WireHeader {
        self.header
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(WIRE_HEADER_BYTES + self.payload.len());
        encoded.extend_from_slice(&self.header.encode());
        encoded.extend_from_slice(&self.payload);
        encoded
    }

    fn validate_semantics(&self) -> WireResult<()> {
        let arg0 = self.header.arg0;
        let arg1 = self.header.arg1;
        match self.header.command {
            WireCommand::Cnxn => {
                AdbProtocolVersion::from_peer_advertisement(arg0)?;
                if arg1 == 0
                    || arg1 as usize > MAX_WIRE_PAYLOAD_BYTES
                    || !valid_connection_banner(&self.payload)
                {
                    return Err(AdbWireError::MalformedFrame(
                        "invalid CNXN max-data or banner",
                    ));
                }
            }
            WireCommand::Auth => {
                if arg1 != 0 {
                    return Err(AdbWireError::MalformedFrame("AUTH arg1 must be zero"));
                }
                match arg0 {
                    value if value == AuthKind::Token as u32 => {
                        if self.payload.len() != AUTH_TOKEN_BYTES {
                            return Err(AdbWireError::MalformedFrame(
                                "AUTH token must contain exactly 20 bytes",
                            ));
                        }
                    }
                    value if value == AuthKind::Signature as u32 => {
                        if self.payload.len() != AUTH_SIGNATURE_BYTES {
                            return Err(AdbWireError::MalformedFrame(
                                "AUTH signature must contain exactly 256 bytes",
                            ));
                        }
                    }
                    _ => {
                        return Err(AdbWireError::MalformedFrame(
                            "unsupported AUTH subtype; public-key enrollment is absent",
                        ));
                    }
                }
            }
            WireCommand::Open => {
                if arg0 == 0
                    || arg1 != 0
                    || self.payload.len() > MAX_SERVICE_BYTES
                    || !SelfAdbdService::accepts_wire_payload(&self.payload)
                {
                    return Err(AdbWireError::MalformedFrame(
                        "invalid OPEN ids or service outside the closed typed set",
                    ));
                }
            }
            WireCommand::Okay => {
                if arg0 == 0 || arg1 == 0 || !self.payload.is_empty() {
                    return Err(AdbWireError::MalformedFrame(
                        "OKAY requires two non-zero ids and no payload",
                    ));
                }
            }
            WireCommand::Wrte => {
                if arg0 == 0 || arg1 == 0 {
                    return Err(AdbWireError::MalformedFrame(
                        "WRTE requires two non-zero ids",
                    ));
                }
            }
            WireCommand::Clse => {
                if (arg0 == 0 && arg1 == 0) || !self.payload.is_empty() {
                    return Err(AdbWireError::MalformedFrame(
                        "CLSE requires at least one stream id and no payload",
                    ));
                }
            }
        }
        Ok(())
    }
}

fn valid_connection_banner(value: &[u8]) -> bool {
    !value.is_empty() && value.len() <= MAX_BANNER_BYTES && !value.contains(&0)
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("fixed u32 span"),
    )
}

#[must_use]
pub fn adb_checksum(payload: &[u8]) -> u32 {
    payload
        .iter()
        .fold(0_u32, |sum, byte| sum.wrapping_add(u32::from(*byte)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegotiatedConnection {
    pub peer_protocol_version: AdbProtocolVersion,
    pub negotiated_protocol_version: AdbProtocolVersion,
    pub peer_max_data: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    New,
    AwaitingHandshake,
    AwaitingAuthSignature,
    Ready {
        connection: NegotiatedConnection,
    },
    Opening {
        local_id: u32,
        connection: NegotiatedConnection,
    },
    Open {
        local_id: u32,
        remote_id: u32,
        connection: NegotiatedConnection,
        awaiting_write_ack: bool,
    },
    Closing {
        local_id: u32,
        remote_id: u32,
        connection: NegotiatedConnection,
    },
    Closed,
    Failed,
}

impl SessionState {
    fn name(&self) -> &'static str {
        match self {
            Self::New => "new",
            Self::AwaitingHandshake => "awaiting_handshake",
            Self::AwaitingAuthSignature => "awaiting_auth_signature",
            Self::Ready { .. } => "ready",
            Self::Opening { .. } => "opening",
            Self::Open { .. } => "open",
            Self::Closing { .. } => "closing",
            Self::Closed => "closed",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    AuthenticationChallenge([u8; AUTH_TOKEN_BYTES]),
    Connected { connection: NegotiatedConnection },
    StreamOpened { local_id: u32, remote_id: u32 },
    WriteAcknowledged,
    Data(Vec<u8>),
    StreamRejected,
    ClosedByPeer,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionStep {
    pub event: SessionEvent,
    pub reply: Option<WireFrame>,
}

/// A single-stream, client-side ADB state machine. It does not perform I/O or
/// own authentication material.
#[derive(Debug, Clone)]
pub struct SelfAdbdSession {
    state: SessionState,
    current_auth_token: Option<[u8; AUTH_TOKEN_BYTES]>,
    seen_auth_tokens: Vec<[u8; AUTH_TOKEN_BYTES]>,
}

impl Default for SelfAdbdSession {
    fn default() -> Self {
        Self::new()
    }
}

impl SelfAdbdSession {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: SessionState::New,
            current_auth_token: None,
            seen_auth_tokens: Vec::new(),
        }
    }

    #[must_use]
    pub const fn state(&self) -> &SessionState {
        &self.state
    }

    pub fn begin(&mut self) -> WireResult<WireFrame> {
        if self.state != SessionState::New {
            return self.fail_unexpected(WireCommand::Cnxn);
        }
        let frame = WireFrame::new(
            WireCommand::Cnxn,
            CLIENT_ADVERTISED_PROTOCOL_VERSION.as_raw(),
            HOST_MAX_DATA,
            FIXED_HOST_BANNER.to_vec(),
        )?;
        self.state = SessionState::AwaitingHandshake;
        Ok(frame)
    }

    pub fn answer_auth_challenge(&mut self, signature: &[u8]) -> WireResult<WireFrame> {
        if self.state != SessionState::AwaitingAuthSignature || self.current_auth_token.is_none() {
            return self.fail_unexpected(WireCommand::Auth);
        }
        let frame = WireFrame::new(
            WireCommand::Auth,
            AuthKind::Signature as u32,
            0,
            signature.to_vec(),
        )?;
        self.current_auth_token = None;
        self.state = SessionState::AwaitingHandshake;
        Ok(frame)
    }

    pub fn open(&mut self, local_id: u32, service: SelfAdbdService) -> WireResult<WireFrame> {
        let SessionState::Ready { connection } = self.state else {
            return self.fail_unexpected(WireCommand::Open);
        };
        let frame = WireFrame::new(
            WireCommand::Open,
            local_id,
            0,
            service.wire_payload().to_vec(),
        )?;
        self.state = SessionState::Opening {
            local_id,
            connection,
        };
        Ok(frame)
    }

    pub fn write(&mut self, payload: &[u8]) -> WireResult<WireFrame> {
        let SessionState::Open {
            local_id,
            remote_id,
            connection,
            awaiting_write_ack: false,
        } = self.state
        else {
            return self.fail_unexpected(WireCommand::Wrte);
        };
        if payload.len() > connection.peer_max_data as usize {
            return Err(AdbWireError::PayloadTooLarge {
                length: payload.len(),
                maximum: connection.peer_max_data as usize,
            });
        }
        let frame = WireFrame::new(WireCommand::Wrte, local_id, remote_id, payload.to_vec())?;
        self.state = SessionState::Open {
            local_id,
            remote_id,
            connection,
            awaiting_write_ack: true,
        };
        Ok(frame)
    }

    pub fn close(&mut self) -> WireResult<Option<WireFrame>> {
        match self.state.clone() {
            SessionState::Ready { .. } => {
                self.state = SessionState::Closed;
                Ok(None)
            }
            SessionState::Opening { local_id, .. } => {
                let frame = WireFrame::new(WireCommand::Clse, local_id, 0, Vec::new())?;
                self.state = SessionState::Closed;
                Ok(Some(frame))
            }
            SessionState::Open {
                local_id,
                remote_id,
                connection,
                ..
            } => {
                let frame = WireFrame::new(WireCommand::Clse, local_id, remote_id, Vec::new())?;
                self.state = SessionState::Closing {
                    local_id,
                    remote_id,
                    connection,
                };
                Ok(Some(frame))
            }
            SessionState::Closed => Err(AdbWireError::SessionClosed),
            _ => self.fail_unexpected(WireCommand::Clse),
        }
    }

    pub fn receive(&mut self, frame: WireFrame) -> WireResult<SessionStep> {
        if self.state == SessionState::Closed {
            return Err(AdbWireError::SessionClosed);
        }
        match self.state.clone() {
            SessionState::AwaitingHandshake => self.receive_handshake(frame),
            SessionState::Opening {
                local_id,
                connection,
            } => self.receive_opening(frame, local_id, connection),
            SessionState::Open {
                local_id,
                remote_id,
                connection,
                awaiting_write_ack,
            } => self.receive_open(frame, local_id, remote_id, connection, awaiting_write_ack),
            SessionState::Closing {
                local_id,
                remote_id,
                ..
            } => self.receive_closing(frame, local_id, remote_id),
            _ => self.fail_unexpected(frame.header.command),
        }
    }

    fn receive_handshake(&mut self, frame: WireFrame) -> WireResult<SessionStep> {
        match frame.header.command {
            WireCommand::Cnxn => {
                let peer_protocol_version =
                    AdbProtocolVersion::from_peer_advertisement(frame.header.arg0)?;
                let connection = NegotiatedConnection {
                    peer_protocol_version,
                    negotiated_protocol_version: peer_protocol_version.negotiate_with_client(),
                    peer_max_data: frame.header.arg1.min(HOST_MAX_DATA),
                };
                self.state = SessionState::Ready { connection };
                Ok(SessionStep {
                    event: SessionEvent::Connected { connection },
                    reply: None,
                })
            }
            WireCommand::Auth if frame.header.arg0 == AuthKind::Token as u32 => {
                let token: [u8; AUTH_TOKEN_BYTES] = frame
                    .payload
                    .as_slice()
                    .try_into()
                    .map_err(|_| AdbWireError::MalformedFrame("invalid AUTH token length"))?;
                if self.seen_auth_tokens.contains(&token) {
                    self.state = SessionState::Failed;
                    return Err(AdbWireError::AuthenticationReplay);
                }
                if self.seen_auth_tokens.len() >= MAX_AUTH_CHALLENGES {
                    self.state = SessionState::Failed;
                    return Err(AdbWireError::AuthenticationLimitExceeded);
                }
                self.seen_auth_tokens.push(token);
                self.current_auth_token = Some(token);
                self.state = SessionState::AwaitingAuthSignature;
                Ok(SessionStep {
                    event: SessionEvent::AuthenticationChallenge(token),
                    reply: None,
                })
            }
            _ => self.fail_unexpected(frame.header.command),
        }
    }

    fn receive_opening(
        &mut self,
        frame: WireFrame,
        local_id: u32,
        connection: NegotiatedConnection,
    ) -> WireResult<SessionStep> {
        match frame.header.command {
            WireCommand::Okay if frame.header.arg1 == local_id => {
                let remote_id = frame.header.arg0;
                self.state = SessionState::Open {
                    local_id,
                    remote_id,
                    connection,
                    awaiting_write_ack: false,
                };
                Ok(SessionStep {
                    event: SessionEvent::StreamOpened {
                        local_id,
                        remote_id,
                    },
                    reply: None,
                })
            }
            WireCommand::Clse if frame.header.arg1 == local_id => {
                self.state = SessionState::Closed;
                Ok(SessionStep {
                    event: SessionEvent::StreamRejected,
                    reply: None,
                })
            }
            WireCommand::Okay | WireCommand::Clse => {
                self.state = SessionState::Failed;
                Err(AdbWireError::StreamIdMismatch)
            }
            _ => self.fail_unexpected(frame.header.command),
        }
    }

    fn receive_open(
        &mut self,
        frame: WireFrame,
        local_id: u32,
        remote_id: u32,
        connection: NegotiatedConnection,
        awaiting_write_ack: bool,
    ) -> WireResult<SessionStep> {
        if frame.header.arg0 != remote_id || frame.header.arg1 != local_id {
            self.state = SessionState::Failed;
            return Err(AdbWireError::StreamIdMismatch);
        }
        match frame.header.command {
            WireCommand::Okay if awaiting_write_ack => {
                self.state = SessionState::Open {
                    local_id,
                    remote_id,
                    connection,
                    awaiting_write_ack: false,
                };
                Ok(SessionStep {
                    event: SessionEvent::WriteAcknowledged,
                    reply: None,
                })
            }
            WireCommand::Wrte => {
                if frame.payload.len() > connection.peer_max_data as usize {
                    self.state = SessionState::Failed;
                    return Err(AdbWireError::PayloadTooLarge {
                        length: frame.payload.len(),
                        maximum: connection.peer_max_data as usize,
                    });
                }
                let reply = WireFrame::new(WireCommand::Okay, local_id, remote_id, Vec::new())?;
                Ok(SessionStep {
                    event: SessionEvent::Data(frame.payload),
                    reply: Some(reply),
                })
            }
            WireCommand::Clse => {
                let reply = WireFrame::new(WireCommand::Clse, local_id, remote_id, Vec::new())?;
                self.state = SessionState::Closed;
                Ok(SessionStep {
                    event: SessionEvent::ClosedByPeer,
                    reply: Some(reply),
                })
            }
            _ => self.fail_unexpected(frame.header.command),
        }
    }

    fn receive_closing(
        &mut self,
        frame: WireFrame,
        local_id: u32,
        remote_id: u32,
    ) -> WireResult<SessionStep> {
        if frame.header.command != WireCommand::Clse {
            return self.fail_unexpected(frame.header.command);
        }
        if frame.header.arg0 != remote_id || frame.header.arg1 != local_id {
            self.state = SessionState::Failed;
            return Err(AdbWireError::StreamIdMismatch);
        }
        self.state = SessionState::Closed;
        Ok(SessionStep {
            event: SessionEvent::Closed,
            reply: None,
        })
    }

    fn fail_unexpected<T>(&mut self, command: WireCommand) -> WireResult<T> {
        let state = self.state.name();
        self.state = SessionState::Failed;
        Err(AdbWireError::UnexpectedCommand { state, command })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    #[derive(Debug, Default)]
    struct MemoryTransport {
        connected: Option<(SelfAdbdEndpoint, StrictTimeout)>,
        writes: Vec<(Vec<u8>, StrictTimeout)>,
        reads: VecDeque<Vec<u8>>,
        read_bounds: Vec<(usize, StrictTimeout)>,
        shutdown_timeout: Option<StrictTimeout>,
    }

    impl BoundedWireTransport for MemoryTransport {
        fn connect(
            &mut self,
            endpoint: SelfAdbdEndpoint,
            timeout: StrictTimeout,
        ) -> WireResult<()> {
            self.connected = Some((endpoint, timeout));
            Ok(())
        }

        fn write_frame(&mut self, frame: &[u8], timeout: StrictTimeout) -> WireResult<()> {
            self.writes.push((frame.to_vec(), timeout));
            Ok(())
        }

        fn read_frame(
            &mut self,
            maximum_bytes: usize,
            timeout: StrictTimeout,
        ) -> WireResult<Vec<u8>> {
            self.read_bounds.push((maximum_bytes, timeout));
            self.reads
                .pop_front()
                .ok_or(AdbWireError::Transport("mock input exhausted"))
        }

        fn shutdown(&mut self, timeout: StrictTimeout) -> WireResult<()> {
            self.shutdown_timeout = Some(timeout);
            Ok(())
        }
    }

    fn cnxn_with_version(version: AdbProtocolVersion) -> WireFrame {
        WireFrame::new(
            WireCommand::Cnxn,
            version.as_raw(),
            4096,
            b"device::features=shell_v2;".to_vec(),
        )
        .unwrap()
    }

    fn cnxn() -> WireFrame {
        cnxn_with_version(AdbProtocolVersion::Checksummed)
    }

    fn negotiated_connection(peer_protocol_version: AdbProtocolVersion) -> NegotiatedConnection {
        NegotiatedConnection {
            peer_protocol_version,
            negotiated_protocol_version: AdbProtocolVersion::Checksummed,
            peer_max_data: 4096,
        }
    }

    fn connected_session() -> SelfAdbdSession {
        let mut session = SelfAdbdSession::new();
        session.begin().unwrap();
        assert_eq!(
            session.receive(cnxn()).unwrap().event,
            SessionEvent::Connected {
                connection: negotiated_connection(AdbProtocolVersion::Checksummed)
            }
        );
        session
    }

    fn open_session() -> SelfAdbdSession {
        let mut session = connected_session();
        session.open(7, SelfAdbdService::ShellV2Raw).unwrap();
        let opened = session
            .receive(WireFrame::new(WireCommand::Okay, 19, 7, Vec::new()).unwrap())
            .unwrap();
        assert_eq!(
            opened.event,
            SessionEvent::StreamOpened {
                local_id: 7,
                remote_id: 19
            }
        );
        session
    }

    #[test]
    fn fixed_target_rejects_serial_hostnames_and_other_ports() {
        let endpoint =
            SelfAdbdEndpoint::validate_untrusted("127.0.0.1", FIXED_SELF_ADBD_PORT, None).unwrap();
        assert_eq!(
            endpoint.socket_addr(),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, FIXED_SELF_ADBD_PORT)
        );
        assert!(
            SelfAdbdEndpoint::validate_untrusted(
                "127.0.0.1",
                FIXED_SELF_ADBD_PORT,
                Some("any-serial")
            )
            .is_err()
        );
        assert!(SelfAdbdEndpoint::validate_untrusted("localhost", 5555, None).is_err());
        assert!(SelfAdbdEndpoint::validate_untrusted("127.0.0.2", 5555, None).is_err());
        assert!(SelfAdbdEndpoint::validate_untrusted("127.0.0.1", 5037, None).is_err());
    }

    #[test]
    fn timeout_and_memory_transport_are_explicitly_bounded() {
        assert!(StrictTimeout::from_millis(0).is_err());
        assert!(StrictTimeout::from_millis(MAX_OPERATION_TIMEOUT_MS + 1).is_err());
        let timeout = StrictTimeout::from_millis(250).unwrap();
        let mut transport = MemoryTransport::default();
        transport
            .connect(SelfAdbdEndpoint::fixed(), timeout)
            .unwrap();
        let begin = SelfAdbdSession::new().begin().unwrap();
        transport_write(&mut transport, &begin, timeout).unwrap();
        transport.reads.push_back(cnxn().encode());
        assert_eq!(transport_read(&mut transport, timeout).unwrap(), cnxn());
        transport.shutdown(timeout).unwrap();
        assert_eq!(
            transport.connected,
            Some((SelfAdbdEndpoint::fixed(), timeout))
        );
        assert_eq!(transport.writes[0].1, timeout);
        assert_eq!(transport.read_bounds, vec![(MAX_WIRE_FRAME_BYTES, timeout)]);
        assert_eq!(transport.shutdown_timeout, Some(timeout));
    }

    #[test]
    fn frame_round_trip_covers_the_closed_command_set() {
        let frames = [
            cnxn(),
            WireFrame::new(
                WireCommand::Auth,
                AuthKind::Token as u32,
                0,
                vec![3; AUTH_TOKEN_BYTES],
            )
            .unwrap(),
            WireFrame::new(
                WireCommand::Open,
                1,
                0,
                SelfAdbdService::ShellV2Raw.wire_payload().to_vec(),
            )
            .unwrap(),
            WireFrame::new(WireCommand::Okay, 2, 1, Vec::new()).unwrap(),
            WireFrame::new(WireCommand::Wrte, 2, 1, b"payload".to_vec()).unwrap(),
            WireFrame::new(WireCommand::Clse, 2, 1, Vec::new()).unwrap(),
        ];
        for frame in frames {
            assert_eq!(WireFrame::decode(&frame.encode()).unwrap(), frame);
        }
        let mut unknown = cnxn().encode();
        let raw = u32::from_le_bytes(*b"SYNC");
        unknown[0..4].copy_from_slice(&raw.to_le_bytes());
        unknown[20..24].copy_from_slice(&(raw ^ u32::MAX).to_le_bytes());
        assert!(matches!(
            WireFrame::decode(&unknown),
            Err(AdbWireError::UnknownCommand(value)) if value == raw
        ));
    }

    #[test]
    fn modern_peer_version_negotiates_to_client_checksummed_version() {
        let mut session = SelfAdbdSession::new();
        let client_cnxn = session.begin().unwrap();
        assert_eq!(
            client_cnxn.header.arg0,
            AdbProtocolVersion::Checksummed.as_raw()
        );
        assert!(!client_cnxn.payload().contains(&0));

        let peer_cnxn = cnxn_with_version(AdbProtocolVersion::ChecksumSkip);
        assert_eq!(
            session.receive(peer_cnxn.clone()).unwrap().event,
            SessionEvent::Connected {
                connection: negotiated_connection(AdbProtocolVersion::ChecksumSkip)
            }
        );
        assert_eq!(
            session.state(),
            &SessionState::Ready {
                connection: negotiated_connection(AdbProtocolVersion::ChecksumSkip)
            }
        );

        // AOSP advertises 1.1 in the initial peer CNXN while its transport is
        // still initialized to 1.0. Because this client advertises 1.0, the
        // negotiated session remains checksummed and a zero checksum is never
        // accepted merely because the peer advertised checksum-skip support.
        let mut without_checksum = peer_cnxn.encode();
        without_checksum[16..20].copy_from_slice(&0_u32.to_le_bytes());
        assert_eq!(
            WireFrame::decode(&without_checksum).unwrap_err(),
            AdbWireError::MalformedFrame("payload checksum mismatch")
        );
    }

    #[test]
    fn peer_versions_outside_aosp_1_0_and_1_1_are_rejected() {
        for advertised in [
            CHECKSUMMED_PROTOCOL_VERSION - 1,
            CHECKSUM_SKIP_PROTOCOL_VERSION + 1,
        ] {
            assert_eq!(
                WireFrame::new(
                    WireCommand::Cnxn,
                    advertised,
                    4096,
                    b"device::features=shell_v2;".to_vec(),
                )
                .unwrap_err(),
                AdbWireError::UnsupportedProtocolVersion { advertised }
            );
        }
    }

    #[test]
    fn open_accepts_only_closed_typed_device_services() {
        for (service, expected) in [
            (SelfAdbdService::ShellV2Raw, b"shell,v2,raw:\0".as_slice()),
            (SelfAdbdService::Sync, b"sync:\0".as_slice()),
        ] {
            let mut session = connected_session();
            let open = session.open(7, service).unwrap();
            assert_eq!(open.payload(), expected);
        }

        for forbidden in [b"root:\0".as_slice(), b"remount:\0", b"unknown:\0"] {
            assert!(matches!(
                WireFrame::new(WireCommand::Open, 7, 0, forbidden.to_vec()),
                Err(AdbWireError::MalformedFrame(
                    "invalid OPEN ids or service outside the closed typed set"
                ))
            ));
        }
    }

    #[test]
    fn malformed_header_magic_checksum_and_lengths_are_rejected() {
        let encoded = cnxn().encode();

        let mut bad_magic = encoded.clone();
        bad_magic[20] ^= 1;
        assert!(matches!(
            WireFrame::decode(&bad_magic),
            Err(AdbWireError::MalformedHeader("command magic mismatch"))
        ));

        let mut bad_checksum = encoded.clone();
        *bad_checksum.last_mut().unwrap() ^= 1;
        assert!(matches!(
            WireFrame::decode(&bad_checksum),
            Err(AdbWireError::MalformedFrame("payload checksum mismatch"))
        ));

        let mut declared_too_long = encoded.clone();
        declared_too_long[12..16]
            .copy_from_slice(&((MAX_WIRE_PAYLOAD_BYTES as u32) + 1).to_le_bytes());
        assert!(matches!(
            WireFrame::decode(&declared_too_long),
            Err(AdbWireError::PayloadTooLarge { .. })
        ));

        let mut wrong_length = encoded;
        wrong_length.pop();
        assert!(matches!(
            WireFrame::decode(&wrong_length),
            Err(AdbWireError::MalformedFrame(
                "payload length does not match header"
            ))
        ));
    }

    #[test]
    fn auth_challenge_requires_external_signature_and_rejects_replay() {
        let token = [0x5a; AUTH_TOKEN_BYTES];
        let challenge =
            WireFrame::new(WireCommand::Auth, AuthKind::Token as u32, 0, token.to_vec()).unwrap();
        let mut session = SelfAdbdSession::new();
        session.begin().unwrap();
        assert_eq!(
            session.receive(challenge.clone()).unwrap().event,
            SessionEvent::AuthenticationChallenge(token)
        );
        let signature = session.answer_auth_challenge(&[0x33; 256]).unwrap();
        assert_eq!(signature.header.command, WireCommand::Auth);
        assert_eq!(signature.header.arg0, AuthKind::Signature as u32);
        assert_eq!(signature.payload.len(), 256);
        assert_eq!(
            session.receive(challenge).unwrap_err(),
            AdbWireError::AuthenticationReplay
        );
        assert_eq!(session.state(), &SessionState::Failed);
    }

    #[test]
    fn auth_challenge_count_is_bounded() {
        let mut session = SelfAdbdSession::new();
        session.begin().unwrap();
        for value in 0..MAX_AUTH_CHALLENGES {
            let token = vec![value as u8; AUTH_TOKEN_BYTES];
            session
                .receive(
                    WireFrame::new(WireCommand::Auth, AuthKind::Token as u32, 0, token).unwrap(),
                )
                .unwrap();
            session
                .answer_auth_challenge(&[1; AUTH_SIGNATURE_BYTES])
                .unwrap();
        }
        let excess = WireFrame::new(
            WireCommand::Auth,
            AuthKind::Token as u32,
            0,
            vec![0xff; AUTH_TOKEN_BYTES],
        )
        .unwrap();
        assert_eq!(
            session.receive(excess).unwrap_err(),
            AdbWireError::AuthenticationLimitExceeded
        );
    }

    #[test]
    fn state_machine_opens_writes_acknowledges_reads_and_closes() {
        let mut session = open_session();
        let write = session.write(b"input tap 10 20").unwrap();
        assert_eq!(write.header.command, WireCommand::Wrte);
        assert!(session.write(b"second write before OKAY").is_err());
        // Recreate because the invalid transition deliberately poisons the
        // state, as every unexpected protocol transition must fail closed.
        let mut session = open_session();
        session.write(b"input tap 10 20").unwrap();
        assert_eq!(
            session
                .receive(WireFrame::new(WireCommand::Okay, 19, 7, Vec::new()).unwrap())
                .unwrap()
                .event,
            SessionEvent::WriteAcknowledged
        );
        let inbound = session
            .receive(WireFrame::new(WireCommand::Wrte, 19, 7, b"done".to_vec()).unwrap())
            .unwrap();
        assert_eq!(inbound.event, SessionEvent::Data(b"done".to_vec()));
        let reply = inbound.reply.unwrap();
        assert_eq!(reply.header.command, WireCommand::Okay);
        assert_eq!((reply.header.arg0, reply.header.arg1), (7, 19));

        let close = session.close().unwrap().unwrap();
        assert_eq!(close.header.command, WireCommand::Clse);
        assert_eq!(
            session
                .receive(WireFrame::new(WireCommand::Clse, 19, 7, Vec::new()).unwrap())
                .unwrap()
                .event,
            SessionEvent::Closed
        );
        assert_eq!(session.state(), &SessionState::Closed);
    }

    #[test]
    fn negotiated_payload_limit_and_stale_ack_are_rejected() {
        let mut session = open_session();
        assert!(matches!(
            session.write(&vec![0; 4097]),
            Err(AdbWireError::PayloadTooLarge {
                length: 4097,
                maximum: 4096
            })
        ));

        let mut session = open_session();
        assert!(matches!(
            session.receive(WireFrame::new(WireCommand::Okay, 19, 7, Vec::new()).unwrap()),
            Err(AdbWireError::UnexpectedCommand {
                command: WireCommand::Okay,
                ..
            })
        ));
        assert_eq!(session.state(), &SessionState::Failed);
    }

    #[test]
    fn peer_close_is_acknowledged_once_and_terminal() {
        let mut session = open_session();
        let close = WireFrame::new(WireCommand::Clse, 19, 7, Vec::new()).unwrap();
        let step = session.receive(close.clone()).unwrap();
        assert_eq!(step.event, SessionEvent::ClosedByPeer);
        assert_eq!(step.reply.unwrap().header.command, WireCommand::Clse);
        assert_eq!(
            session.receive(close).unwrap_err(),
            AdbWireError::SessionClosed
        );
    }

    #[test]
    fn auth_public_key_enrollment_and_invalid_command_states_are_closed() {
        assert!(WireFrame::new(WireCommand::Auth, 3, 0, b"key\0".to_vec()).is_err());
        assert!(
            WireFrame::new(
                WireCommand::Auth,
                AuthKind::Signature as u32,
                0,
                vec![0; AUTH_SIGNATURE_BYTES - 1],
            )
            .is_err()
        );
        let mut session = SelfAdbdSession::new();
        let okay = WireFrame::new(WireCommand::Okay, 2, 1, Vec::new()).unwrap();
        assert!(session.receive(okay).is_err());
        assert_eq!(session.state(), &SessionState::Failed);
    }

    fn digest(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn custody(generation: u64) -> AdbKeyCustody {
        AdbKeyCustody::OsOwned {
            handle_id: format!("adb-key-handle-{generation}"),
            public_key_sha256: digest('a'),
            generation,
        }
    }

    #[test]
    fn typed_operations_stay_in_android_adb_namespace_and_use_graduated_tiers() {
        let operations = [
            AndroidAdbOperation::Devices,
            AndroidAdbOperation::GetState,
            AndroidAdbOperation::InspectDevice,
            AndroidAdbOperation::Shell,
            AndroidAdbOperation::Push,
            AndroidAdbOperation::Pull,
            AndroidAdbOperation::Install,
            AndroidAdbOperation::Uninstall,
            AndroidAdbOperation::Reboot,
            AndroidAdbOperation::Root,
            AndroidAdbOperation::Remount,
            AndroidAdbOperation::Sideload,
            AndroidAdbOperation::Flash,
        ];
        for operation in operations {
            assert!(operation.as_str().starts_with("android.adb."));
            assert!(!operation.as_str().starts_with("rootlinux.exec."));
            assert!(operation.minimum_tier().allows(operation));
        }
        assert!(AndroidAdbTier::ReadOnly.allows(AndroidAdbOperation::Devices));
        assert!(!AndroidAdbTier::ReadOnly.allows(AndroidAdbOperation::Shell));
        assert!(AndroidAdbTier::User.allows(AndroidAdbOperation::Shell));
        assert!(!AndroidAdbTier::User.allows(AndroidAdbOperation::Install));
        assert!(AndroidAdbTier::Developer.allows(AndroidAdbOperation::Reboot));
        assert!(!AndroidAdbTier::Developer.allows(AndroidAdbOperation::Remount));
        assert!(AndroidAdbTier::Recovery.allows(AndroidAdbOperation::Flash));
    }

    #[test]
    fn transport_domains_are_closed_and_disjoint_before_dispatch() {
        assert_eq!(
            AgentTransportDomain::classify("android.adb.shell.v1").unwrap(),
            AgentTransportDomain::AndroidAdb
        );
        assert_eq!(
            AgentTransportDomain::classify("rootlinux.exec.shell.v1").unwrap(),
            AgentTransportDomain::RootLinuxExec
        );
        assert!(AgentTransportDomain::classify("adb.shell.v1").is_err());
        assert!(
            AgentTransportDomain::classify("rootlinux.exec.shell.v1").unwrap()
                != AgentTransportDomain::AndroidAdb
        );
    }

    #[test]
    fn device_binding_and_key_rotation_are_monotonic_and_bounded() {
        let binding = DeviceBinding {
            binding_id: "device-binding-1".to_string(),
            device_identity_sha256: digest('1'),
            build_fingerprint_sha256: digest('2'),
            avb_public_key_sha256: digest('3'),
            binding_generation: 1,
            key_generation: 1,
        };
        binding.validate().unwrap();

        let initial = KeyRotationPolicy {
            current_generation: 1,
            previous_generation: None,
            overlap_until_boot: None,
            custody: custody(1),
        };
        initial.validate().unwrap();
        assert!(binding.validate_key_generation(&initial, 100).is_ok());

        let rotated = initial.rotate(2, Some(110), custody(2)).unwrap();
        assert!(rotated.accepts_generation(2, 10_000));
        assert!(rotated.accepts_generation(1, 110));
        assert!(!rotated.accepts_generation(1, 111));
        assert!(rotated.rotate(2, Some(120), custody(2)).is_err());
        assert!(rotated.rotate(1, Some(120), custody(1)).is_err());

        let stale_binding = DeviceBinding {
            key_generation: 1,
            ..binding
        };
        assert!(
            stale_binding
                .validate_key_generation(&rotated, 111)
                .is_err()
        );
    }

    #[test]
    fn model_request_is_closed_typed_and_does_not_carry_key_custody() {
        let request = AdbTransportRequest::new(
            "adb-request-1".to_string(),
            AndroidAdbOperation::Shell,
            "device-binding-1".to_string(),
            AndroidAdbArguments::Shell {
                argv: vec!["getprop".to_string(), "ro.build.fingerprint".to_string()],
            },
        )
        .unwrap();
        let encoded = serde_json::to_vec(&request).unwrap();
        assert!(!String::from_utf8_lossy(&encoded).contains("private_key"));
        let decoded = parse_android_adb_model_request(&encoded).unwrap();
        assert_eq!(decoded, request);

        let binding = DeviceBinding {
            binding_id: "device-binding-1".to_string(),
            device_identity_sha256: digest('1'),
            build_fingerprint_sha256: digest('2'),
            avb_public_key_sha256: digest('3'),
            binding_generation: 1,
            key_generation: 1,
        };
        let rotation = KeyRotationPolicy::new(1, custody(1)).unwrap();
        let read_only = AndroidAdbPermissionGrant {
            tier: AndroidAdbTier::ReadOnly,
            expires_at_boot: Some(10),
            user_confirmation_required: false,
        };
        assert!(
            request
                .validate_admission(&binding, &rotation, read_only, 5)
                .is_err()
        );
        let user_grant = AndroidAdbPermissionGrant {
            tier: AndroidAdbTier::User,
            ..read_only
        };
        request
            .validate_admission(&binding, &rotation, user_grant, 5)
            .unwrap();

        let with_host = serde_json::json!({
            "protocol_version": ANDROID_ADB_CONTRACT_VERSION,
            "request_id": "adb-request-1",
            "operation": "shell",
            "device_binding": "device-binding-1",
            "arguments": {"kind": "shell", "argv": ["id"]},
            "host": "127.0.0.1",
        });
        assert!(parse_android_adb_model_request(&serde_json::to_vec(&with_host).unwrap()).is_err());
    }

    #[test]
    fn model_request_rejects_permanent_private_key_material_before_deserialization() {
        let malicious = serde_json::json!({
            "protocol_version": ANDROID_ADB_CONTRACT_VERSION,
            "request_id": "adb-request-1",
            "operation": "devices",
            "device_binding": SELF_DEVICE_BINDING_REF,
            "arguments": {"kind": "empty"},
            "private_key_pem": "-----BEGIN PRIVATE KEY-----deadbeef",
        });
        assert!(matches!(
            parse_android_adb_model_request(&serde_json::to_vec(&malicious).unwrap()),
            Err(AndroidAdbContractError::PrivateKeyMaterialForbidden { .. })
        ));
        // Direct serde callers receive the same fail-closed boundary; the
        // helper is not an optional security hook.
        assert!(serde_json::from_value::<AdbTransportRequest>(malicious).is_err());

        let nested = serde_json::json!({
            "protocol_version": ANDROID_ADB_CONTRACT_VERSION,
            "request_id": "adb-request-1",
            "operation": "devices",
            "device_binding": SELF_DEVICE_BINDING_REF,
            "arguments": {"kind": "empty"},
            "metadata": {"key_material": "opaque-but-forbidden"},
        });
        assert!(matches!(
            parse_android_adb_model_request(&serde_json::to_vec(&nested).unwrap()),
            Err(AndroidAdbContractError::PrivateKeyMaterialForbidden { .. })
        ));

        let lowercase_pem = serde_json::json!({
            "protocol_version": ANDROID_ADB_CONTRACT_VERSION,
            "request_id": "adb-request-1",
            "operation": "devices",
            "device_binding": SELF_DEVICE_BINDING_REF,
            "arguments": {"kind": "shell", "argv": ["-----begin private key-----"]},
        });
        assert!(matches!(
            parse_android_adb_model_request(&serde_json::to_vec(&lowercase_pem).unwrap()),
            Err(AndroidAdbContractError::PrivateKeyMaterialForbidden { .. })
        ));
    }
}
