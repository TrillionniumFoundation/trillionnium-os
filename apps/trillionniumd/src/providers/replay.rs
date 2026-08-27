//! Durable cross-boot idempotency records for state-changing Agent UDS calls.
//!
//! The store persists a `pending` record before dispatch and the exact response
//! after dispatch. A daemon or kernel restart can therefore return a
//! completed response or fail closed on an incomplete operation. Request IDs
//! are never cleared on a kernel boot transition. Response bodies may be
//! compacted under quota pressure, but the identity-bound tombstone remains
//! and can only deny replay, never authorize re-execution.

use std::collections::HashSet;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use trillionnium_os_types::now_unix_ms;

const REPLAY_SCHEMA: &str = "trillionnium.agent-api-replay.cross-boot.v6";
const LEGACY_OPENED_EXECUTABLE_REPLAY_SCHEMA: &str = "trillionnium.agent-api-replay.cross-boot.v5";
const LEGACY_DIGEST_ONLY_REPLAY_SCHEMA: &str = "trillionnium.agent-api-replay.cross-boot.v4";
const LEGACY_CROSS_BOOT_REPLAY_SCHEMA: &str = "trillionnium.agent-api-replay.cross-boot.v3";
const LEGACY_BOOT_SCOPED_REPLAY_SCHEMA: &str = "trillionnium.agent-api-replay.boot-scoped.v2";
const DEFAULT_REPLAY_PATH: &str = "/var/lib/trillionnium/agent-api-replay.json";
const DEFAULT_BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";
const MAX_REPLAY_RECORDS: usize = 65_536;
const MAX_REPLAY_RECORDS_PER_AGENT: usize = 8_192;
const MAX_REPLAY_TOMBSTONES: usize = 131_072;
const MAX_STORE_BYTES: usize = 64 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 262_144;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayIdentity {
    pub uid: u32,
    pub gid: u32,
    pub selinux_domain: String,
    /// SHA-256 of the OS-provisioned agent executable or manifest generation.
    /// Live inode and mode observations deliberately do not enter the durable
    /// replay key: those belong to the connection-lifetime peer guard.
    pub agent_generation_sha256: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ReplayDecision {
    Execute,
    Cached(Value),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayState {
    schema: String,
    boot_id: String,
    records: Vec<ReplayRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayRecord {
    method: String,
    request_id: String,
    agent_id: String,
    peer_uid: u32,
    /// `None` is accepted only while loading v2/v3 records that predate the
    /// independent GID binding. Such records remain permanent fail-closed
    /// tombstones and can never return a cached response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    peer_gid: Option<u32>,
    peer_selinux_domain: String,
    /// Set only when a legacy record lacks a complete stable principal. The
    /// request id remains a permanent tombstone and can never authorize
    /// re-execution.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    legacy_identity_tombstone: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent_generation_sha256: Option<String>,
    /// v5 bound replay to a live opened inode. These fields are accepted only
    /// as migration input and are never serialized into v6.
    #[serde(default, skip_serializing)]
    peer_executable_dev: Option<u64>,
    #[serde(default, skip_serializing)]
    peer_executable_ino: Option<u64>,
    #[serde(default, skip_serializing)]
    peer_executable_uid: Option<u32>,
    #[serde(default, skip_serializing)]
    peer_executable_gid: Option<u32>,
    #[serde(default, skip_serializing)]
    peer_executable_mode: Option<u32>,
    /// v5 and older name for the stable executable/manifest digest. Accepted
    /// only as migration input and never serialized into v6.
    #[serde(default, skip_serializing)]
    peer_executable_sha256: Option<String>,
    request_sha256: String,
    completed: bool,
    response: Option<Value>,
    created_at_unix_ms: u64,
    last_accessed_at_unix_ms: u64,
}

pub struct AgentApiReplayStore {
    path: PathBuf,
    state: ReplayState,
    max_records: usize,
    max_records_per_agent: usize,
}

impl AgentApiReplayStore {
    pub fn open_from_env() -> Result<Self> {
        let path = env::var_os("TRILLIONNIUM_AGENT_API_REPLAY_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_REPLAY_PATH));
        let boot_id_path = env::var_os("TRILLIONNIUM_AGENT_API_BOOT_ID_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_BOOT_ID_PATH));
        let boot_id = read_boot_id(&boot_id_path)?;
        Self::open(&path, &boot_id)
    }

    pub fn open(path: &Path, boot_id: &str) -> Result<Self> {
        if !path.is_absolute() {
            bail!("Agent API replay path must be absolute");
        }
        validate_boot_id(boot_id)?;
        let mut store = Self {
            path: path.to_path_buf(),
            state: ReplayState {
                schema: REPLAY_SCHEMA.to_string(),
                boot_id: boot_id.to_string(),
                records: Vec::new(),
            },
            max_records: MAX_REPLAY_RECORDS,
            max_records_per_agent: MAX_REPLAY_RECORDS_PER_AGENT,
        };
        match read_owner_controlled(path)? {
            Some(bytes) => {
                let persisted: ReplayState =
                    serde_json::from_slice(&bytes).context("invalid Agent API replay JSON")?;
                if persisted.schema != REPLAY_SCHEMA
                    && persisted.schema != LEGACY_OPENED_EXECUTABLE_REPLAY_SCHEMA
                    && persisted.schema != LEGACY_DIGEST_ONLY_REPLAY_SCHEMA
                    && persisted.schema != LEGACY_CROSS_BOOT_REPLAY_SCHEMA
                    && persisted.schema != LEGACY_BOOT_SCOPED_REPLAY_SCHEMA
                {
                    bail!("unsupported Agent API replay schema");
                }
                validate_loaded_state(&persisted, now_unix_ms())?;
                let needs_schema_migration = persisted.schema != REPLAY_SCHEMA;
                let needs_flush = needs_schema_migration || persisted.boot_id != boot_id;
                store.state = persisted;
                if needs_schema_migration {
                    for record in &mut store.state.records {
                        let legacy_generation = record.peer_executable_sha256.take();
                        let has_stable_principal = !record.legacy_identity_tombstone
                            && record.peer_gid.is_some()
                            && legacy_generation.is_some();
                        if has_stable_principal {
                            // v4/v5 already bound UID, GID, SELinux domain and
                            // the provisioned executable digest. Dropping the
                            // ephemeral opened-inode fields is the intended A/B
                            // migration and does not invalidate cached bodies.
                            record.agent_generation_sha256 = legacy_generation;
                        } else {
                            // v2/v3 records without a GID (and prior explicit
                            // tombstones) cannot be widened safely. Preserve the
                            // request id but explicitly discard any response.
                            record.legacy_identity_tombstone = true;
                            record.completed = true;
                            record.response = None;
                            record.agent_generation_sha256 = None;
                        }
                        record.peer_executable_dev = None;
                        record.peer_executable_ino = None;
                        record.peer_executable_uid = None;
                        record.peer_executable_gid = None;
                        record.peer_executable_mode = None;
                    }
                }
                store.state.schema = REPLAY_SCHEMA.to_string();
                store.state.boot_id = boot_id.to_string();
                validate_loaded_state(&store.state, now_unix_ms())?;
                if needs_flush {
                    // Preserve every pending/completed identity across the boot
                    // transition; only the diagnostic current-boot marker changes.
                    store.flush()?;
                }
            }
            None => store.flush()?,
        }
        Ok(store)
    }

    pub fn begin(
        &mut self,
        identity: &ReplayIdentity,
        agent_id: &str,
        method: &str,
        request_id: &str,
        request_sha256: &str,
    ) -> Result<ReplayDecision> {
        if !is_state_changing_method(method) {
            bail!("Agent API replay accepts only state-changing methods");
        }
        validate_agent_id(agent_id)?;
        validate_security_context(&identity.selinux_domain)?;
        validate_digest(&identity.agent_generation_sha256)?;
        validate_request_id(request_id)?;
        validate_digest(request_sha256)?;
        let now = now_unix_ms();
        if let Some(index) = self.find_request_id(request_id) {
            if !self.binding_matches(index, identity, agent_id, method) {
                bail!("request_id_replay_binding_mismatch");
            }
            let (completed, response) = {
                let record = &mut self.state.records[index];
                if record.request_sha256 != request_sha256 {
                    bail!("request_id_replay_payload_mismatch");
                }
                record.last_accessed_at_unix_ms = now;
                (record.completed, record.response.clone())
            };
            self.flush()?;
            return if completed {
                match response {
                    Some(response) => Ok(ReplayDecision::Cached(response)),
                    None => bail!("request_id_completed_response_compacted_use_fresh_id"),
                }
            } else {
                bail!("request_id_incomplete_requires_fresh_id")
            };
        }
        while self.active_agent_record_count(identity, agent_id) >= self.max_records_per_agent
            && self.compact_oldest_completed_response_for(Some((identity, agent_id)))
        {}
        if self.active_agent_record_count(identity, agent_id) >= self.max_records_per_agent {
            bail!("agent_api_replay_agent_active_quota_exhausted");
        }
        while self.active_record_count() >= self.max_records
            && self.compact_oldest_completed_response_for(None)
        {}
        if self.active_record_count() >= self.max_records {
            bail!("agent_api_replay_global_active_quota_exhausted");
        }
        if self.state.records.len() >= MAX_REPLAY_TOMBSTONES {
            bail!("agent_api_replay_tombstone_capacity_exhausted_fail_closed");
        }
        self.state.records.push(ReplayRecord {
            method: method.to_string(),
            request_id: request_id.to_string(),
            agent_id: agent_id.to_string(),
            peer_uid: identity.uid,
            peer_gid: Some(identity.gid),
            peer_selinux_domain: identity.selinux_domain.clone(),
            legacy_identity_tombstone: false,
            agent_generation_sha256: Some(identity.agent_generation_sha256.clone()),
            peer_executable_dev: None,
            peer_executable_ino: None,
            peer_executable_uid: None,
            peer_executable_gid: None,
            peer_executable_mode: None,
            peer_executable_sha256: None,
            request_sha256: request_sha256.to_string(),
            completed: false,
            response: None,
            created_at_unix_ms: now,
            last_accessed_at_unix_ms: now,
        });
        self.flush()?;
        Ok(ReplayDecision::Execute)
    }

    fn active_agent_record_count(&self, identity: &ReplayIdentity, agent_id: &str) -> usize {
        self.state
            .records
            .iter()
            .filter(|record| {
                record.agent_id == agent_id
                    && record.peer_uid == identity.uid
                    && record.peer_gid == Some(identity.gid)
                    && record.peer_selinux_domain == identity.selinux_domain
                    && record.agent_generation_sha256.as_deref()
                        == Some(identity.agent_generation_sha256.as_str())
                    && (!record.completed || record.response.is_some())
            })
            .count()
    }

    fn active_record_count(&self) -> usize {
        self.state
            .records
            .iter()
            .filter(|record| !record.completed || record.response.is_some())
            .count()
    }

    pub fn complete(
        &mut self,
        identity: &ReplayIdentity,
        agent_id: &str,
        method: &str,
        request_id: &str,
        request_sha256: &str,
        response: &Value,
    ) -> Result<()> {
        let encoded = serde_json::to_vec(response)?;
        if encoded.len() > MAX_RESPONSE_BYTES {
            bail!("Agent API replay response exceeds bounded frame size");
        }
        let index = self
            .find_request_id(request_id)
            .context("Agent API replay reservation disappeared")?;
        if !self.binding_matches(index, identity, agent_id, method) {
            bail!("request_id_replay_binding_mismatch");
        }
        let record = &mut self.state.records[index];
        if record.request_sha256 != request_sha256 {
            bail!("request_id_replay_payload_mismatch");
        }
        record.completed = true;
        record.response = Some(response.clone());
        record.last_accessed_at_unix_ms = now_unix_ms();
        if let Err(error) = self.flush() {
            if let Some(index) = self.find_request_id(request_id) {
                self.state.records[index].completed = false;
                self.state.records[index].response = None;
            }
            return Err(error);
        }
        Ok(())
    }

    fn find_request_id(&self, request_id: &str) -> Option<usize> {
        self.state
            .records
            .iter()
            .position(|record| record.request_id == request_id)
    }

    fn binding_matches(
        &self,
        index: usize,
        identity: &ReplayIdentity,
        agent_id: &str,
        method: &str,
    ) -> bool {
        let record = &self.state.records[index];
        record.method == method
            && record.agent_id == agent_id
            && record.peer_uid == identity.uid
            && record.peer_gid == Some(identity.gid)
            && record.peer_selinux_domain == identity.selinux_domain
            && record.agent_generation_sha256.as_deref()
                == Some(identity.agent_generation_sha256.as_str())
    }

    fn compact_oldest_completed_response(&mut self) -> bool {
        self.compact_oldest_completed_response_for(None)
    }

    fn compact_oldest_completed_response_for(
        &mut self,
        owner: Option<(&ReplayIdentity, &str)>,
    ) -> bool {
        if let Some((index, _)) = self
            .state
            .records
            .iter()
            .enumerate()
            .filter(|(_, record)| {
                record.completed
                    && record.response.is_some()
                    && owner.is_none_or(|(identity, agent_id)| {
                        record.agent_id == agent_id
                            && record.peer_uid == identity.uid
                            && record.peer_gid == Some(identity.gid)
                            && record.peer_selinux_domain == identity.selinux_domain
                            && record.agent_generation_sha256.as_deref()
                                == Some(identity.agent_generation_sha256.as_str())
                    })
            })
            .min_by_key(|(_, record)| record.last_accessed_at_unix_ms)
        {
            self.state.records[index].response = None;
            true
        } else {
            false
        }
    }

    fn flush(&mut self) -> Result<()> {
        let parent = self
            .path
            .parent()
            .context("Agent API replay path has no parent")?
            .to_path_buf();
        fs::create_dir_all(&parent)
            .with_context(|| format!("failed to create replay directory {}", parent.display()))?;
        reject_symlink_components(&parent)?;
        let parent_metadata = fs::symlink_metadata(&parent)
            .with_context(|| format!("failed to inspect replay directory {}", parent.display()))?;
        let euid = unsafe { libc::geteuid() };
        if parent_metadata.file_type().is_symlink()
            || !parent_metadata.is_dir()
            || parent_metadata.uid() != euid
            || parent_metadata.permissions().mode() & 0o077 != 0
        {
            bail!("Agent API replay directory is not owner-controlled");
        }
        let mut bytes = serde_json::to_vec_pretty(&self.state)?;
        while bytes.len().saturating_add(1) > MAX_STORE_BYTES {
            if !self.compact_oldest_completed_response() {
                bail!(
                    "Agent API replay store exceeds disk bound with only pending/tombstone records"
                );
            }
            bytes = serde_json::to_vec_pretty(&self.state)?;
        }
        bytes.push(b'\n');
        let temporary = parent.join(format!(
            ".agent-api-replay.tmp-{}-{}",
            std::process::id(),
            now_unix_ms()
        ));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)
            .with_context(|| format!("failed to create {}", temporary.display()))?;
        let publish = (|| -> Result<()> {
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, &self.path).with_context(|| {
                format!(
                    "failed to atomically publish replay store {}",
                    self.path.display()
                )
            })?;
            File::open(&parent)?.sync_all()?;
            Ok(())
        })();
        if publish.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        publish
    }
}

fn read_owner_controlled(path: &Path) -> Result<Option<Vec<u8>>> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to open {}", path.display()));
        }
    };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.nlink() != 1
        || metadata.len() > MAX_STORE_BYTES as u64
    {
        bail!("Agent API replay file is not an owner-controlled bounded regular file");
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(Some(bytes))
}

fn reject_symlink_components(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).with_context(|| {
            format!(
                "failed to inspect replay path component {}",
                current.display()
            )
        })?;
        if metadata.file_type().is_symlink() {
            bail!(
                "Agent API replay path contains a symlink: {}",
                current.display()
            );
        }
    }
    Ok(())
}

fn validate_loaded_state(state: &ReplayState, now: u64) -> Result<()> {
    validate_boot_id(&state.boot_id)?;
    if state.records.len() > MAX_REPLAY_TOMBSTONES {
        bail!("Agent API replay tombstone count exceeds the hard cap");
    }
    let mut keys = HashSet::with_capacity(state.records.len());
    for record in &state.records {
        if !is_state_changing_method(&record.method) {
            bail!("Agent API replay record contains a non-state-changing method");
        }
        validate_request_id(&record.request_id)?;
        validate_agent_id(&record.agent_id)?;
        validate_security_context(&record.peer_selinux_domain)?;
        let opened_identity = (
            record.peer_executable_dev,
            record.peer_executable_ino,
            record.peer_executable_uid,
            record.peer_executable_gid,
            record.peer_executable_mode,
        );
        let has_complete_opened_identity = matches!(
            opened_identity,
            (Some(dev), Some(ino), Some(_), Some(_), Some(mode))
                if dev != 0 && ino != 0 && mode <= 0o7777 && mode & 0o111 != 0 && mode & 0o7022 == 0
        );
        let has_no_opened_identity = matches!(opened_identity, (None, None, None, None, None));
        if state.schema == REPLAY_SCHEMA {
            if record.peer_executable_sha256.is_some() || !has_no_opened_identity {
                bail!("Agent API replay v6 record contains legacy opened executable identity");
            }
            if record.legacy_identity_tombstone {
                if record.agent_generation_sha256.is_some()
                    || !record.completed
                    || record.response.is_some()
                {
                    bail!("Agent API replay legacy identity tombstone is malformed");
                }
            } else {
                let generation = record
                    .agent_generation_sha256
                    .as_deref()
                    .context("Agent API replay v6 record lacks an agent generation digest")?;
                validate_digest(generation)?;
                if record.peer_gid.is_none() {
                    bail!("Agent API replay v6 record lacks a peer GID");
                }
            }
        } else {
            if record.agent_generation_sha256.is_some() {
                bail!("legacy Agent API replay record contains a v6 generation field");
            }
            let legacy_generation = record
                .peer_executable_sha256
                .as_deref()
                .context("legacy Agent API replay record lacks an executable digest")?;
            validate_digest(legacy_generation)?;
            if state.schema == LEGACY_OPENED_EXECUTABLE_REPLAY_SCHEMA {
                if record.legacy_identity_tombstone {
                    if !has_no_opened_identity || !record.completed || record.response.is_some() {
                        bail!("Agent API replay legacy identity tombstone is malformed");
                    }
                } else if !has_complete_opened_identity || record.peer_gid.is_none() {
                    bail!("Agent API replay v5 record lacks a complete identity");
                }
            } else if !has_no_opened_identity {
                bail!("legacy Agent API replay record has an opened executable identity");
            }
        }
        validate_digest(&record.request_sha256)?;
        if record.created_at_unix_ms > record.last_accessed_at_unix_ms
            || record.last_accessed_at_unix_ms > now.saturating_add(5 * 60 * 1_000)
        {
            bail!("Agent API replay record contains invalid timestamps");
        }
        if record.response.is_some() && !record.completed {
            bail!("Agent API replay pending record contains a response");
        }
        if let Some(response) = &record.response
            && serde_json::to_vec(response)?.len() > MAX_RESPONSE_BYTES
        {
            bail!("Agent API replay record contains an oversized response");
        }
        if !keys.insert(record.request_id.clone()) {
            bail!("Agent API replay store contains a duplicate request id");
        }
    }
    Ok(())
}

fn is_state_changing_method(method: &str) -> bool {
    matches!(
        method,
        "register_agent" | "create_task" | "submit_plan" | "run_tool" | "cancel_task"
    )
}

fn validate_agent_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("invalid Agent API replay agent id");
    }
    Ok(())
}

fn validate_security_context(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        bail!("invalid Agent API replay security context");
    }
    Ok(())
}

fn read_boot_id(path: &Path) -> Result<String> {
    let boot_id = fs::read_to_string(path)
        .with_context(|| format!("failed to read boot id {}", path.display()))?;
    let boot_id = boot_id.trim().to_string();
    validate_boot_id(&boot_id)?;
    Ok(boot_id)
}

fn validate_boot_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        bail!("invalid kernel boot id");
    }
    Ok(())
}

pub fn validate_request_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        bail!("invalid Agent API request_id");
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("invalid Agent API request digest");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> ReplayIdentity {
        ReplayIdentity {
            uid: 62_020,
            gid: 62_021,
            selinux_domain: "u:r:unregistered_agent:s0".to_string(),
            agent_generation_sha256: "a".repeat(64),
        }
    }

    #[test]
    fn completed_response_survives_daemon_restart_and_mismatch_fails() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("replay.json");
        let response = serde_json::json!({"ok": true, "result": {"task": "task-1"}});
        {
            let mut store = AgentApiReplayStore::open(&path, "boot-fixture-1").unwrap();
            assert_eq!(
                store
                    .begin(
                        &identity(),
                        "agent-fixture",
                        "create_task",
                        "request-1",
                        &"b".repeat(64),
                    )
                    .unwrap(),
                ReplayDecision::Execute
            );
            store
                .complete(
                    &identity(),
                    "agent-fixture",
                    "create_task",
                    "request-1",
                    &"b".repeat(64),
                    &response,
                )
                .unwrap();
        }
        let mut restarted = AgentApiReplayStore::open(&path, "boot-fixture-1").unwrap();
        assert_eq!(
            restarted
                .begin(
                    &identity(),
                    "agent-fixture",
                    "create_task",
                    "request-1",
                    &"b".repeat(64),
                )
                .unwrap(),
            ReplayDecision::Cached(response)
        );
        let persisted: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(persisted["schema"], REPLAY_SCHEMA);
        assert_eq!(persisted["records"][0]["peer_uid"], identity().uid);
        assert_eq!(persisted["records"][0]["peer_gid"], identity().gid);
        assert_eq!(
            persisted["records"][0]["agent_generation_sha256"],
            identity().agent_generation_sha256
        );
        assert!(persisted["records"][0].get("peer_executable_dev").is_none());
        assert!(persisted["records"][0].get("peer_executable_ino").is_none());
        assert!(
            persisted["records"][0]
                .get("peer_executable_mode")
                .is_none()
        );
        let mut wrong_gid = identity();
        wrong_gid.gid += 1;
        assert!(
            restarted
                .begin(
                    &wrong_gid,
                    "agent-fixture",
                    "create_task",
                    "request-1",
                    &"b".repeat(64),
                )
                .unwrap_err()
                .to_string()
                .contains("binding_mismatch")
        );
        assert!(
            restarted
                .begin(
                    &identity(),
                    "agent-fixture",
                    "create_task",
                    "request-1",
                    &"c".repeat(64),
                )
                .unwrap_err()
                .to_string()
                .contains("payload_mismatch")
        );

        let mut upgraded_executable = identity();
        upgraded_executable.agent_generation_sha256 = "d".repeat(64);
        assert!(
            restarted
                .begin(
                    &upgraded_executable,
                    "agent-fixture",
                    "create_task",
                    "request-1",
                    &"b".repeat(64),
                )
                .unwrap_err()
                .to_string()
                .contains("binding_mismatch")
        );
    }

    #[test]
    fn pending_record_survives_restart_and_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("replay.json");
        let mut store = AgentApiReplayStore::open(&path, "boot-pending-test").unwrap();
        store
            .begin(
                &identity(),
                "agent-fixture",
                "run_tool",
                "request-pending",
                &"e".repeat(64),
            )
            .unwrap();
        drop(store);
        let mut restarted = AgentApiReplayStore::open(&path, "boot-pending-test").unwrap();
        assert!(
            restarted
                .begin(
                    &identity(),
                    "agent-fixture",
                    "run_tool",
                    "request-pending",
                    &"e".repeat(64),
                )
                .unwrap_err()
                .to_string()
                .contains("incomplete_requires_fresh_id")
        );
    }

    #[test]
    fn request_id_cannot_cross_method_agent_or_peer_binding() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("replay.json");
        let mut store = AgentApiReplayStore::open(&path, "boot-binding-test").unwrap();

        store
            .begin(
                &identity(),
                "agent-fixture",
                "create_task",
                "request-cross-method",
                &"f".repeat(64),
            )
            .unwrap();
        assert!(
            store
                .begin(
                    &identity(),
                    "agent-fixture",
                    "cancel_task",
                    "request-cross-method",
                    &"f".repeat(64),
                )
                .unwrap_err()
                .to_string()
                .contains("binding_mismatch")
        );

        store
            .begin(
                &identity(),
                "agent-fixture",
                "create_task",
                "request-cross-agent",
                &"1".repeat(64),
            )
            .unwrap();
        assert!(
            store
                .begin(
                    &identity(),
                    "agent-other",
                    "create_task",
                    "request-cross-agent",
                    &"1".repeat(64),
                )
                .unwrap_err()
                .to_string()
                .contains("binding_mismatch")
        );

        store
            .begin(
                &identity(),
                "agent-fixture",
                "create_task",
                "request-cross-peer",
                &"2".repeat(64),
            )
            .unwrap();
        let mut other_peer = identity();
        other_peer.uid += 1;
        assert!(
            store
                .begin(
                    &other_peer,
                    "agent-fixture",
                    "create_task",
                    "request-cross-peer",
                    &"2".repeat(64),
                )
                .unwrap_err()
                .to_string()
                .contains("binding_mismatch")
        );

        store
            .begin(
                &identity(),
                "agent-fixture",
                "create_task",
                "request-cross-gid",
                &"3".repeat(64),
            )
            .unwrap();
        let mut other_group = identity();
        other_group.gid += 1;
        assert!(
            store
                .begin(
                    &other_group,
                    "agent-fixture",
                    "create_task",
                    "request-cross-gid",
                    &"3".repeat(64),
                )
                .unwrap_err()
                .to_string()
                .contains("binding_mismatch")
        );
    }

    #[test]
    fn legacy_gid_unbound_record_migrates_to_permanent_fail_closed_tombstone() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("replay.json");
        let now = now_unix_ms();
        let legacy = serde_json::json!({
            "schema": LEGACY_CROSS_BOOT_REPLAY_SCHEMA,
            "boot_id": "boot-legacy-gid",
            "records": [{
                "method": "create_task",
                "request_id": "request-legacy-gid",
                "agent_id": "agent-fixture",
                "peer_uid": identity().uid,
                "peer_selinux_domain": identity().selinux_domain,
                "peer_executable_sha256": identity().agent_generation_sha256,
                "request_sha256": "4".repeat(64),
                "completed": true,
                "response": {"ok": true, "result": {"task": "legacy-task"}},
                "created_at_unix_ms": now,
                "last_accessed_at_unix_ms": now
            }]
        });
        fs::write(&path, serde_json::to_vec_pretty(&legacy).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let mut migrated = AgentApiReplayStore::open(&path, "boot-after-gid-hardening").unwrap();
        let persisted: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(persisted["schema"], REPLAY_SCHEMA);
        assert!(persisted["records"][0].get("peer_gid").is_none());
        assert_eq!(persisted["records"][0]["legacy_identity_tombstone"], true);
        assert!(persisted["records"][0]["response"].is_null());
        assert!(
            migrated
                .begin(
                    &identity(),
                    "agent-fixture",
                    "create_task",
                    "request-legacy-gid",
                    &"4".repeat(64),
                )
                .unwrap_err()
                .to_string()
                .contains("binding_mismatch")
        );

        drop(migrated);
        let mut restarted = AgentApiReplayStore::open(&path, "boot-after-gid-hardening").unwrap();
        assert!(
            restarted
                .begin(
                    &identity(),
                    "agent-fixture",
                    "create_task",
                    "request-legacy-gid",
                    &"4".repeat(64),
                )
                .unwrap_err()
                .to_string()
                .contains("binding_mismatch")
        );
    }

    #[test]
    fn v4_complete_stable_identity_migrates_without_destroying_cached_response() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("replay.json");
        let now = now_unix_ms();
        let legacy = serde_json::json!({
            "schema": LEGACY_DIGEST_ONLY_REPLAY_SCHEMA,
            "boot_id": "boot-v4-identity",
            "records": [{
                "method": "run_tool",
                "request_id": "request-v4-identity",
                "agent_id": "agent-fixture",
                "peer_uid": identity().uid,
                "peer_gid": identity().gid,
                "peer_selinux_domain": identity().selinux_domain,
                "peer_executable_sha256": identity().agent_generation_sha256,
                "request_sha256": "7".repeat(64),
                "completed": true,
                "response": {"ok": true, "result": {"receipt": "must-not-leak"}},
                "created_at_unix_ms": now,
                "last_accessed_at_unix_ms": now
            }]
        });
        fs::write(&path, serde_json::to_vec_pretty(&legacy).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let response = serde_json::json!({"ok": true, "result": {"receipt": "must-not-leak"}});
        let mut migrated = AgentApiReplayStore::open(&path, "boot-v6-first").unwrap();
        assert_eq!(
            migrated
                .begin(
                    &identity(),
                    "agent-fixture",
                    "run_tool",
                    "request-v4-identity",
                    &"7".repeat(64),
                )
                .unwrap(),
            ReplayDecision::Cached(response.clone())
        );
        drop(migrated);

        let persisted: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(persisted["schema"], REPLAY_SCHEMA);
        assert!(
            persisted["records"][0]
                .get("legacy_identity_tombstone")
                .is_none()
        );
        assert_eq!(persisted["records"][0]["response"], response);
        assert!(
            persisted["records"][0]
                .get("peer_executable_sha256")
                .is_none()
        );
        let mut reopened = AgentApiReplayStore::open(&path, "boot-v6-second").unwrap();
        assert_eq!(
            reopened
                .begin(
                    &identity(),
                    "agent-fixture",
                    "run_tool",
                    "request-v4-identity",
                    &"7".repeat(64),
                )
                .unwrap(),
            ReplayDecision::Cached(response)
        );
    }

    #[test]
    fn v5_same_digest_after_new_inode_migrates_to_cached_response() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("replay.json");
        let now = now_unix_ms();
        let response = serde_json::json!({"ok": true, "result": {"task": "stable"}});
        let legacy = serde_json::json!({
            "schema": LEGACY_OPENED_EXECUTABLE_REPLAY_SCHEMA,
            "boot_id": "boot-v5-inode-41",
            "records": [{
                "method": "create_task",
                "request_id": "request-v5-new-inode",
                "agent_id": "agent-fixture",
                "peer_uid": identity().uid,
                "peer_gid": identity().gid,
                "peer_selinux_domain": identity().selinux_domain,
                "peer_executable_dev": 40,
                "peer_executable_ino": 41,
                "peer_executable_uid": 0,
                "peer_executable_gid": 0,
                "peer_executable_mode": 0o755,
                "peer_executable_sha256": identity().agent_generation_sha256,
                "request_sha256": "9".repeat(64),
                "completed": true,
                "response": response,
                "created_at_unix_ms": now,
                "last_accessed_at_unix_ms": now
            }]
        });
        fs::write(&path, serde_json::to_vec_pretty(&legacy).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        // The current live connection may now refer to a different device and
        // inode after an A/B slot switch. ReplayIdentity intentionally contains
        // only the provisioned stable generation, so the exact retry still hits.
        let mut migrated = AgentApiReplayStore::open(&path, "boot-v6-inode-99").unwrap();
        assert_eq!(
            migrated
                .begin(
                    &identity(),
                    "agent-fixture",
                    "create_task",
                    "request-v5-new-inode",
                    &"9".repeat(64),
                )
                .unwrap(),
            ReplayDecision::Cached(response.clone())
        );

        let mut different_generation = identity();
        different_generation.agent_generation_sha256 = "e".repeat(64);
        let error = migrated
            .begin(
                &different_generation,
                "agent-fixture",
                "create_task",
                "request-v5-new-inode",
                &"9".repeat(64),
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("binding_mismatch"), "{error}");

        let persisted: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(persisted["records"][0]["response"], response);
        assert!(persisted["records"][0].get("peer_executable_dev").is_none());
        assert!(persisted["records"][0].get("peer_executable_ino").is_none());
        assert_eq!(
            persisted["records"][0]["agent_generation_sha256"],
            identity().agent_generation_sha256
        );
    }

    #[test]
    fn boot_transition_preserves_completed_response_and_never_reexecutes() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("replay.json");
        let mut first = AgentApiReplayStore::open(&path, "boot-fixture-1").unwrap();
        first
            .begin(
                &identity(),
                "agent-fixture",
                "cancel_task",
                "request-2",
                &"d".repeat(64),
            )
            .unwrap();
        let response = serde_json::json!({"ok": true, "cancelled": true});
        first
            .complete(
                &identity(),
                "agent-fixture",
                "cancel_task",
                "request-2",
                &"d".repeat(64),
                &response,
            )
            .unwrap();
        drop(first);
        let mut second = AgentApiReplayStore::open(&path, "boot-fixture-2").unwrap();
        assert_eq!(
            second
                .begin(
                    &identity(),
                    "agent-fixture",
                    "cancel_task",
                    "request-2",
                    &"d".repeat(64),
                )
                .unwrap(),
            ReplayDecision::Cached(response)
        );
    }

    #[test]
    fn completed_bodies_compact_under_quota_but_tombstones_never_reexecute() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("replay.json");
        let mut store = AgentApiReplayStore::open(&path, "boot-no-eviction-test").unwrap();
        store.max_records = 2;
        store.max_records_per_agent = 2;
        for suffix in ["one", "two"] {
            let request_id = format!("request-{suffix}");
            let response = serde_json::json!({"ok": true, "request": suffix});
            assert_eq!(
                store
                    .begin(
                        &identity(),
                        "agent-fixture",
                        "create_task",
                        &request_id,
                        &"7".repeat(64),
                    )
                    .unwrap(),
                ReplayDecision::Execute
            );
            store
                .complete(
                    &identity(),
                    "agent-fixture",
                    "create_task",
                    &request_id,
                    &"7".repeat(64),
                    &response,
                )
                .unwrap();
        }
        assert_eq!(
            store
                .begin(
                    &identity(),
                    "agent-fixture",
                    "create_task",
                    "request-three",
                    &"7".repeat(64),
                )
                .unwrap(),
            ReplayDecision::Execute
        );
        assert!(
            store
                .begin(
                    &identity(),
                    "agent-fixture",
                    "create_task",
                    "request-one",
                    &"7".repeat(64),
                )
                .unwrap_err()
                .to_string()
                .contains("completed_response_compacted_use_fresh_id")
        );
    }

    #[test]
    fn compacted_response_tombstone_cannot_reexecute() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("replay.json");
        let mut store = AgentApiReplayStore::open(&path, "boot-tombstone-test").unwrap();
        store
            .begin(
                &identity(),
                "agent-fixture",
                "run_tool",
                "request-compacted",
                &"8".repeat(64),
            )
            .unwrap();
        store
            .complete(
                &identity(),
                "agent-fixture",
                "run_tool",
                "request-compacted",
                &"8".repeat(64),
                &serde_json::json!({"ok": true}),
            )
            .unwrap();
        assert!(store.compact_oldest_completed_response());
        store.flush().unwrap();
        drop(store);

        let mut restarted = AgentApiReplayStore::open(&path, "boot-tombstone-test").unwrap();
        assert!(
            restarted
                .begin(
                    &identity(),
                    "agent-fixture",
                    "run_tool",
                    "request-compacted",
                    &"8".repeat(64),
                )
                .unwrap_err()
                .to_string()
                .contains("completed_response_compacted_use_fresh_id")
        );
    }
}
