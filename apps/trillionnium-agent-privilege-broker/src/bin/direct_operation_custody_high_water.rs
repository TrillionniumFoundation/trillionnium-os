use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use trillionnium_os_types::direct_operation_custody_high_water::{
    DIRECT_OPERATION_CUSTODY_HIGH_WATER_CONFIRMATION_ACK_SCHEMA,
    DIRECT_OPERATION_CUSTODY_HIGH_WATER_PROTOCOL,
    DIRECT_OPERATION_CUSTODY_HIGH_WATER_RESPONSE_SCHEMA, DirectOperationCustodyHead,
    DirectOperationCustodyHighWaterClientFrameV1,
    DirectOperationCustodyHighWaterConfirmationDisposition,
    DirectOperationCustodyHighWaterDisposition, DirectOperationCustodyHighWaterOperation,
    DirectOperationCustodyHighWaterRequestV1,
    DirectOperationCustodyHighWaterResponseConfirmationAckV1,
    DirectOperationCustodyHighWaterResponseConfirmationV1,
    DirectOperationCustodyHighWaterResponseV1, DirectOperationCustodyHighWaterRouteV1,
    DirectOperationCustodyHighWaterServerFrameV1, transition_sha256,
};
use trillionnium_os_types::sha256_bytes;

const COMPILED_VARIANT: &str = env!("TRILLIONNIUM_P01_CONFORMANCE_BUILD_VARIANT");
const FIXED_STATE_ROOT: &str = "/data/trillionnium/root-linux/rootfs/var/lib/trillionnium/direct-operation-custody/high-water-authority-v2";
const FIXED_SOCKET_PATH: &str = "/data/trillionnium/root-linux/rootfs/run/trillionnium/direct-operation-custody-high-water-v2.sock";
const FIXED_CUSTODY_STORE_PATH: &str =
    "/var/lib/trillionnium/direct-operation-custody/custody-v1.json";
const FIXED_CLIENT_JOURNAL_ROOT: &str =
    "/var/lib/trillionnium/direct-operation-custody/high-water-client-v2";
const ROUTE_SOCKET_PATH: &str = "/run/trillionnium/direct-operation-custody-high-water-v2.sock";
const FIXED_AUTHORITY_DOMAIN: &str = "u:r:trillionnium_direct_operation_custody_high_water:s0";
const FIXED_CLIENT_DOMAIN: &str = "u:r:trillionnium_agentd:s0";
const FIXED_AUTHORITY_IDENTITY_SHA256: &str =
    "1b6a5712e17d79f896a915ba02b5b44a743db3700fb753e8f14f7f625b7e4a40";
const STATE_SCHEMA: &str = "trillionnium.direct-operation-custody-high-water-authority.v2";
const STATE_DOMAIN: &[u8] = b"trillionnium.direct-operation-custody-high-water-authority.v2";
const STATE_FILE: &str = "authority-state-v2.json";
const NEXT_FILE: &str = "authority-state-v2.next";
const MAX_FRAME_BYTES: usize = 64 * 1024;
const MAX_STATE_BYTES: usize = 4 * 1024 * 1024;
const MAX_RESOLVED: usize = 4096;

#[repr(C)]
struct CapabilityHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
struct CapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[used]
#[unsafe(link_section = ".trillionnium.p01.high-water.variant")]
static VARIANT_MARKER: [u8; 96] = variant_marker();

const fn variant_marker() -> [u8; 96] {
    let source = b"org.trillionnium.p01.high-water.compiled-variant.v1=userdebug";
    let mut output = [0u8; 96];
    let mut index = 0;
    while index < source.len() {
        output[index] = source[index];
        index += 1;
    }
    output
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingTransition {
    from: DirectOperationCustodyHead,
    to: DirectOperationCustodyHead,
    transition_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingExchange {
    request: DirectOperationCustodyHighWaterRequestV1,
    response: DirectOperationCustodyHighWaterResponseV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolvedExchange {
    request: DirectOperationCustodyHighWaterRequestV1,
    response: DirectOperationCustodyHighWaterResponseV1,
    confirmation: DirectOperationCustodyHighWaterResponseConfirmationV1,
    acknowledgement: DirectOperationCustodyHighWaterResponseConfirmationAckV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityState {
    schema: String,
    revision: u64,
    route: DirectOperationCustodyHighWaterRouteV1,
    committed: DirectOperationCustodyHead,
    pending_transition: Option<PendingTransition>,
    pending_exchange: Option<PendingExchange>,
    resolved: Vec<ResolvedExchange>,
    permanent_hold: bool,
    state_sha256: String,
}

impl AuthorityState {
    fn initial() -> Result<Self> {
        let mut state = Self {
            schema: STATE_SCHEMA.to_string(),
            revision: 0,
            route: product_route()?,
            committed: DirectOperationCustodyHead::genesis(),
            pending_transition: None,
            pending_exchange: None,
            resolved: Vec::new(),
            permanent_hold: false,
            state_sha256: String::new(),
        };
        state.seal()?;
        state.validate()?;
        Ok(state)
    }

    fn validate(&self) -> Result<()> {
        self.route.validate().map_err(|error| anyhow!(error))?;
        self.committed.validate().map_err(|error| anyhow!(error))?;
        if self.schema != STATE_SCHEMA
            || self.resolved.len() > MAX_RESOLVED
            || self.state_sha256 != self.expected_sha256()?
        {
            bail!("direct_operation_custody_high_water_authority_state_denied");
        }
        if let Some(pending) = &self.pending_transition {
            pending.from.validate().map_err(|error| anyhow!(error))?;
            pending.to.validate().map_err(|error| anyhow!(error))?;
            if pending.to.generation
                != pending
                    .from
                    .generation
                    .checked_add(1)
                    .context("direct_operation_custody_high_water_authority_generation_exhausted")?
                || pending.transition_sha256
                    != transition_sha256(&self.route, &pending.from, &pending.to)
            {
                bail!("direct_operation_custody_high_water_authority_pending_denied");
            }
        }
        if let Some(exchange) = &self.pending_exchange {
            validate_exchange(&exchange.request, &exchange.response)?;
        }
        for exchange in &self.resolved {
            validate_exchange(&exchange.request, &exchange.response)?;
            exchange
                .confirmation
                .validate()
                .map_err(|error| anyhow!(error))?;
            exchange
                .acknowledgement
                .validate_for(&exchange.confirmation, FIXED_AUTHORITY_IDENTITY_SHA256)
                .map_err(|error| anyhow!(error))?;
            if exchange.confirmation.operation_id_sha256 != exchange.request.operation_id_sha256
                || exchange.confirmation.request_sha256 != exchange.request.request_sha256
                || exchange.confirmation.response_sha256 != exchange.response.response_sha256
            {
                bail!("direct_operation_custody_high_water_authority_resolved_denied");
            }
        }
        Ok(())
    }

    fn seal(&mut self) -> Result<()> {
        self.state_sha256 = self.expected_sha256()?;
        Ok(())
    }

    fn expected_sha256(&self) -> Result<String> {
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema: &'a str,
            revision: u64,
            route: &'a DirectOperationCustodyHighWaterRouteV1,
            committed: &'a DirectOperationCustodyHead,
            pending_transition: &'a Option<PendingTransition>,
            pending_exchange: &'a Option<PendingExchange>,
            resolved: &'a Vec<ResolvedExchange>,
            permanent_hold: bool,
        }
        canonical_digest(
            STATE_DOMAIN,
            &Preimage {
                schema: &self.schema,
                revision: self.revision,
                route: &self.route,
                committed: &self.committed,
                pending_transition: &self.pending_transition,
                pending_exchange: &self.pending_exchange,
                resolved: &self.resolved,
                permanent_hold: self.permanent_hold,
            },
        )
    }
}

fn main() {
    if run().is_err() {
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    if COMPILED_VARIANT != "userdebug" || std::env::args_os().len() != 1 {
        bail!("direct_operation_custody_high_water_authority_variant_denied");
    }
    let root = Path::new(FIXED_STATE_ROOT);
    let _lease = open_or_initialize_state_root(root)?;
    let listener = bind_fixed_listener(Path::new(FIXED_SOCKET_PATH))?;
    harden_service_process()?;
    clear_environment();
    loop {
        let (mut stream, _) = listener.accept()?;
        if authenticate_client(&stream).is_err() {
            continue;
        }
        if serve_connection(&mut stream, root).is_err() {
            continue;
        }
    }
}

fn product_route() -> Result<DirectOperationCustodyHighWaterRouteV1> {
    DirectOperationCustodyHighWaterRouteV1::derive(
        sha256_bytes(FIXED_CUSTODY_STORE_PATH.as_bytes()),
        sha256_bytes(FIXED_CLIENT_JOURNAL_ROOT.as_bytes()),
        sha256_bytes(ROUTE_SOCKET_PATH.as_bytes()),
        sha256_bytes(FIXED_AUTHORITY_DOMAIN.as_bytes()),
    )
    .map_err(|error| anyhow!(error))
}

fn open_or_initialize_state_root(root: &Path) -> Result<File> {
    match fs::symlink_metadata(root) {
        Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
            bail!("direct_operation_custody_high_water_state_root_type_denied");
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(root)
                .context("direct_operation_custody_high_water_state_root_create")?;
            fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
            persist_state(root, &mut AuthorityState::initial()?)?;
        }
        Err(error) => return Err(error.into()),
    }
    let directory = open_directory_nofollow(root)?;
    validate_directory(&directory)?;
    if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error())
            .context("direct_operation_custody_high_water_authority_singleton_denied");
    }
    load_state(root)?;
    Ok(directory)
}

fn bind_fixed_listener(path: &Path) -> Result<UnixListener> {
    let parent = path
        .parent()
        .context("direct_operation_custody_high_water_socket_parent_missing")?;
    let parent_file = open_directory_nofollow(parent)?;
    validate_socket_parent(&parent_file)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_socket()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.permissions().mode() & 0o7777 != 0o600
            || UnixStream::connect(path).is_ok()
        {
            bail!("direct_operation_custody_high_water_stale_socket_denied");
        }
        fs::remove_file(path)?;
        parent_file.sync_all()?;
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    parent_file.sync_all()?;
    Ok(listener)
}

fn authenticate_client(stream: &UnixStream) -> Result<()> {
    let credentials = peer_credentials(stream)?;
    if credentials.uid != 0
        || credentials.gid != 0
        || credentials.pid <= 0
        || peer_security_context(stream)? != FIXED_CLIENT_DOMAIN
    {
        bail!("direct_operation_custody_high_water_client_identity_denied");
    }
    Ok(())
}

fn serve_connection(stream: &mut UnixStream, root: &Path) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    loop {
        let Some(frame) = read_frame(stream)? else {
            return Ok(());
        };
        let response = match frame {
            DirectOperationCustodyHighWaterClientFrameV1::Operation(request) => {
                DirectOperationCustodyHighWaterServerFrameV1::OperationResponse(process_operation(
                    root, request,
                )?)
            }
            DirectOperationCustodyHighWaterClientFrameV1::ConfirmResponse(confirmation) => {
                DirectOperationCustodyHighWaterServerFrameV1::ConfirmResponseAck(
                    process_confirmation(root, confirmation)?,
                )
            }
        };
        write_frame(stream, &response)?;
    }
}

fn process_operation(
    root: &Path,
    request: DirectOperationCustodyHighWaterRequestV1,
) -> Result<DirectOperationCustodyHighWaterResponseV1> {
    let mut state = load_state(root)?;
    let response = apply_operation(&mut state, &request)?;
    if !state.permanent_hold {
        state.pending_exchange = Some(PendingExchange {
            request,
            response: response.clone(),
        });
    }
    persist_state(root, &mut state)?;
    Ok(response)
}

fn apply_operation(
    state: &mut AuthorityState,
    request: &DirectOperationCustodyHighWaterRequestV1,
) -> Result<DirectOperationCustodyHighWaterResponseV1> {
    request.validate().map_err(|error| anyhow!(error))?;
    if request.route != state.route
        || state.pending_exchange.is_some()
        || state
            .resolved
            .iter()
            .any(|resolved| resolved.request.operation_id_sha256 == request.operation_id_sha256)
    {
        state.permanent_hold = true;
    }
    if state.permanent_hold {
        return response(
            request,
            DirectOperationCustodyHighWaterDisposition::PermanentHold,
            state.committed.clone(),
            request.transition_sha256.clone(),
        );
    }
    let (disposition, response_transition) = match request.operation {
        DirectOperationCustodyHighWaterOperation::Reconcile => {
            if let Some(pending) = state.pending_transition.clone() {
                if request.current_head == pending.from {
                    state.pending_transition = None;
                } else if request.current_head == pending.to {
                    state.committed = pending.to;
                    state.pending_transition = None;
                } else {
                    state.permanent_hold = true;
                }
            } else if request.current_head != state.committed {
                state.permanent_hold = true;
            }
            (
                DirectOperationCustodyHighWaterDisposition::ReconciledExact,
                None,
            )
        }
        DirectOperationCustodyHighWaterOperation::Observe => {
            if state.pending_transition.is_some() || request.current_head != state.committed {
                state.permanent_hold = true;
            }
            (
                DirectOperationCustodyHighWaterDisposition::ObservedExact,
                None,
            )
        }
        DirectOperationCustodyHighWaterOperation::Prepare => {
            let to = request
                .proposed_head
                .clone()
                .context("direct_operation_custody_high_water_prepare_head_missing")?;
            let transition = request
                .transition_sha256
                .clone()
                .context("direct_operation_custody_high_water_prepare_transition_missing")?;
            let pending = PendingTransition {
                from: request.current_head.clone(),
                to,
                transition_sha256: transition.clone(),
            };
            if request.current_head != state.committed
                || state
                    .pending_transition
                    .as_ref()
                    .is_some_and(|existing| existing != &pending)
            {
                state.permanent_hold = true;
            } else {
                state.pending_transition = Some(pending);
            }
            (
                DirectOperationCustodyHighWaterDisposition::PreparedExact,
                Some(transition),
            )
        }
        DirectOperationCustodyHighWaterOperation::Commit => {
            let transition = request
                .transition_sha256
                .clone()
                .context("direct_operation_custody_high_water_commit_transition_missing")?;
            let exact = state.pending_transition.as_ref().is_some_and(|pending| {
                pending.from == state.committed
                    && pending.to == request.current_head
                    && pending.transition_sha256 == transition
            });
            if exact {
                state.committed = request.current_head.clone();
                state.pending_transition = None;
            } else {
                state.permanent_hold = true;
            }
            (
                DirectOperationCustodyHighWaterDisposition::CommittedExact,
                Some(transition),
            )
        }
    };
    if state.permanent_hold {
        response(
            request,
            DirectOperationCustodyHighWaterDisposition::PermanentHold,
            state.committed.clone(),
            request.transition_sha256.clone(),
        )
    } else {
        response(
            request,
            disposition,
            state.committed.clone(),
            response_transition,
        )
    }
}

fn process_confirmation(
    root: &Path,
    confirmation: DirectOperationCustodyHighWaterResponseConfirmationV1,
) -> Result<DirectOperationCustodyHighWaterResponseConfirmationAckV1> {
    confirmation.validate().map_err(|error| anyhow!(error))?;
    let mut state = load_state(root)?;
    if let Some(resolved) = state
        .resolved
        .iter()
        .find(|resolved| resolved.confirmation == confirmation)
    {
        return Ok(resolved.acknowledgement.clone());
    }
    let exact = state.pending_exchange.as_ref().is_some_and(|pending| {
        pending.request.operation == confirmation.operation
            && pending.request.route.route_sha256 == confirmation.route_sha256
            && pending.request.operation_id_sha256 == confirmation.operation_id_sha256
            && pending.request.request_sha256 == confirmation.request_sha256
            && pending.response.response_sha256 == confirmation.response_sha256
    });
    if state.permanent_hold || !exact || state.resolved.len() == MAX_RESOLVED {
        state.permanent_hold = true;
        let acknowledgement = confirmation_ack(
            &confirmation,
            DirectOperationCustodyHighWaterConfirmationDisposition::PermanentHold,
        );
        persist_state(root, &mut state)?;
        return Ok(acknowledgement);
    }
    let pending = state
        .pending_exchange
        .take()
        .context("direct_operation_custody_high_water_pending_disappeared")?;
    let acknowledgement = confirmation_ack(
        &confirmation,
        DirectOperationCustodyHighWaterConfirmationDisposition::ResponseConfirmedExact,
    );
    state.resolved.push(ResolvedExchange {
        request: pending.request,
        response: pending.response,
        confirmation,
        acknowledgement: acknowledgement.clone(),
    });
    persist_state(root, &mut state)?;
    Ok(acknowledgement)
}

fn response(
    request: &DirectOperationCustodyHighWaterRequestV1,
    disposition: DirectOperationCustodyHighWaterDisposition,
    committed_head: DirectOperationCustodyHead,
    transition: Option<String>,
) -> Result<DirectOperationCustodyHighWaterResponseV1> {
    let mut response = DirectOperationCustodyHighWaterResponseV1 {
        schema: DIRECT_OPERATION_CUSTODY_HIGH_WATER_RESPONSE_SCHEMA.to_string(),
        protocol: DIRECT_OPERATION_CUSTODY_HIGH_WATER_PROTOCOL.to_string(),
        operation: request.operation,
        disposition,
        authority_identity_sha256: FIXED_AUTHORITY_IDENTITY_SHA256.to_string(),
        route_sha256: request.route.route_sha256.clone(),
        operation_id_sha256: request.operation_id_sha256.clone(),
        request_sha256: request.request_sha256.clone(),
        committed_head,
        transition_sha256: transition,
        response_sha256: String::new(),
    };
    response.seal();
    response
        .validate_binding_for(request, FIXED_AUTHORITY_IDENTITY_SHA256)
        .map_err(|error| anyhow!(error))?;
    Ok(response)
}

fn confirmation_ack(
    confirmation: &DirectOperationCustodyHighWaterResponseConfirmationV1,
    disposition: DirectOperationCustodyHighWaterConfirmationDisposition,
) -> DirectOperationCustodyHighWaterResponseConfirmationAckV1 {
    let mut acknowledgement = DirectOperationCustodyHighWaterResponseConfirmationAckV1 {
        schema: DIRECT_OPERATION_CUSTODY_HIGH_WATER_CONFIRMATION_ACK_SCHEMA.to_string(),
        protocol: DIRECT_OPERATION_CUSTODY_HIGH_WATER_PROTOCOL.to_string(),
        disposition,
        authority_identity_sha256: FIXED_AUTHORITY_IDENTITY_SHA256.to_string(),
        route_sha256: confirmation.route_sha256.clone(),
        operation_id_sha256: confirmation.operation_id_sha256.clone(),
        request_sha256: confirmation.request_sha256.clone(),
        response_sha256: confirmation.response_sha256.clone(),
        client_response_receipt_sha256: confirmation.client_response_receipt_sha256.clone(),
        confirmation_sha256: confirmation.confirmation_sha256.clone(),
        confirmation_ack_sha256: String::new(),
    };
    acknowledgement.seal();
    acknowledgement
}

fn persist_state(root: &Path, state: &mut AuthorityState) -> Result<()> {
    state.revision = state
        .revision
        .checked_add(1)
        .context("direct_operation_custody_high_water_authority_revision_exhausted")?;
    state.seal()?;
    state.validate()?;
    let bytes = canonical_bytes(state)?;
    if bytes.len() > MAX_STATE_BYTES {
        bail!("direct_operation_custody_high_water_authority_state_too_large");
    }
    let next = root.join(NEXT_FILE);
    let final_path = root.join(STATE_FILE);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&next)
        .context("direct_operation_custody_high_water_authority_next_create")?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    validate_regular(&file, bytes.len())?;
    fs::rename(&next, &final_path)?;
    File::open(root)?.sync_all()?;
    if fs::read(&final_path)? != bytes {
        bail!("direct_operation_custody_high_water_authority_readback_denied");
    }
    Ok(())
}

fn load_state(root: &Path) -> Result<AuthorityState> {
    match fs::symlink_metadata(root.join(NEXT_FILE)) {
        Ok(_) => bail!("direct_operation_custody_high_water_authority_incomplete_publish_hold"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let path = root.join(STATE_FILE);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&path)?;
    let metadata = file.metadata()?;
    if metadata.len() as usize > MAX_STATE_BYTES {
        bail!("direct_operation_custody_high_water_authority_state_size_denied");
    }
    validate_regular(&file, metadata.len() as usize)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_STATE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    let state: AuthorityState = serde_json::from_slice(&bytes)?;
    if canonical_bytes(&state)? != bytes {
        bail!("direct_operation_custody_high_water_authority_noncanonical_state");
    }
    state.validate()?;
    Ok(state)
}

fn validate_directory(file: &File) -> Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != expected_owner_uid()
        || metadata.gid() != expected_owner_gid()
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        bail!("direct_operation_custody_high_water_authority_directory_denied");
    }
    Ok(())
}

fn validate_socket_parent(file: &File) -> Result<()> {
    let metadata = file.metadata()?;
    let mode = metadata.permissions().mode() & 0o7777;
    if !metadata.is_dir()
        || metadata.uid() != expected_owner_uid()
        || metadata.gid() != expected_owner_gid()
        || mode != 0o750
    {
        bail!("direct_operation_custody_high_water_socket_parent_denied");
    }
    Ok(())
}

fn validate_regular(file: &File, expected_len: usize) -> Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != expected_owner_uid()
        || metadata.gid() != expected_owner_gid()
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() != expected_len as u64
    {
        bail!("direct_operation_custody_high_water_authority_file_denied");
    }
    Ok(())
}

fn expected_owner_uid() -> u32 {
    if cfg!(test) {
        unsafe { libc::geteuid() }
    } else {
        0
    }
}

fn expected_owner_gid() -> u32 {
    if cfg!(test) {
        unsafe { libc::getegid() }
    } else {
        0
    }
}

fn validate_exchange(
    request: &DirectOperationCustodyHighWaterRequestV1,
    response: &DirectOperationCustodyHighWaterResponseV1,
) -> Result<()> {
    request.validate().map_err(|error| anyhow!(error))?;
    response
        .validate_binding_for(request, FIXED_AUTHORITY_IDENTITY_SHA256)
        .map_err(|error| anyhow!(error))?;
    response.require_success().map_err(|error| anyhow!(error))?;
    Ok(())
}

fn open_directory_nofollow(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)?)
}

fn harden_service_process() -> Result<()> {
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
        || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        || unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            )
        } != 0
    {
        return Err(io::Error::last_os_error())
            .context("direct_operation_custody_high_water_process_hardening_denied");
    }
    for capability in 0..=63 {
        let result = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) };
        if result != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL) {
            return Err(io::Error::last_os_error())
                .context("direct_operation_custody_high_water_bounding_drop_denied");
        }
    }
    let securebits = libc::SECBIT_NOROOT
        | libc::SECBIT_NOROOT_LOCKED
        | libc::SECBIT_NO_SETUID_FIXUP
        | libc::SECBIT_NO_SETUID_FIXUP_LOCKED
        | libc::SECBIT_NO_CAP_AMBIENT_RAISE
        | libc::SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED;
    if unsafe { libc::prctl(libc::PR_SET_SECUREBITS, securebits, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error())
            .context("direct_operation_custody_high_water_securebits_denied");
    }
    let header = CapabilityHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let data = [
        CapabilityData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        CapabilityData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    if unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error())
            .context("direct_operation_custody_high_water_capset_denied");
    }
    Ok(())
}

fn clear_environment() {
    for name in std::env::vars_os()
        .map(|(name, _)| name)
        .collect::<Vec<_>>()
    {
        unsafe { std::env::remove_var(name) };
    }
}

fn read_frame(
    stream: &mut UnixStream,
) -> Result<Option<DirectOperationCustodyHighWaterClientFrameV1>> {
    let mut prefix = [0u8; 4];
    match stream.read_exact(&mut prefix) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        bail!("direct_operation_custody_high_water_authority_frame_size_denied");
    }
    let mut bytes = vec![0u8; length];
    stream.read_exact(&mut bytes)?;
    let frame = serde_json::from_slice(&bytes)?;
    if canonical_bytes(&frame)? != bytes {
        bail!("direct_operation_custody_high_water_authority_frame_noncanonical");
    }
    Ok(Some(frame))
}

fn write_frame(
    stream: &mut UnixStream,
    frame: &DirectOperationCustodyHighWaterServerFrameV1,
) -> Result<()> {
    let bytes = canonical_bytes(frame)?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        bail!("direct_operation_custody_high_water_authority_response_size_denied");
    }
    stream.write_all(&u32::try_from(bytes.len())?.to_be_bytes())?;
    stream.write_all(&bytes)?;
    stream.flush()?;
    Ok(())
}

fn peer_credentials(stream: &UnixStream) -> Result<libc::ucred> {
    let mut credentials = std::mem::MaybeUninit::<libc::ucred>::zeroed();
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast(),
            &mut length,
        )
    } != 0
        || length as usize != std::mem::size_of::<libc::ucred>()
    {
        return Err(io::Error::last_os_error()).context("peer_credentials_denied");
    }
    Ok(unsafe { credentials.assume_init() })
}

fn peer_security_context(stream: &UnixStream) -> Result<String> {
    let mut bytes = vec![0u8; 4096];
    let mut length = bytes.len() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERSEC,
            bytes.as_mut_ptr().cast(),
            &mut length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error()).context("peer_security_context_denied");
    }
    bytes.truncate(length as usize);
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    String::from_utf8(bytes).context("peer_security_context_utf8_denied")
}

fn canonical_bytes(value: &impl Serialize) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(value)?)
}

fn canonical_digest(domain: &[u8], value: &impl Serialize) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0]);
    hasher.update(canonical_bytes(value)?);
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use trillionnium_os_types::direct_operation_custody_high_water::{
        DirectOperationCustodyHighWaterOperation, DirectOperationCustodyHighWaterRequestV1,
    };

    fn initialized() -> (TempDir, PathBuf) {
        let temporary = TempDir::new().unwrap();
        let root = temporary.path().join("authority");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        persist_state(&root, &mut AuthorityState::initial().unwrap()).unwrap();
        (temporary, root)
    }

    #[test]
    fn socket_parent_requires_canonical_0750_mode() {
        let temporary = TempDir::new().unwrap();
        let parent = temporary.path().join("run");
        fs::create_dir(&parent).unwrap();

        for (mode, expected) in [(0o750, true), (0o700, false), (0o755, false)] {
            fs::set_permissions(&parent, fs::Permissions::from_mode(mode)).unwrap();
            let file = open_directory_nofollow(&parent).unwrap();
            assert_eq!(validate_socket_parent(&file).is_ok(), expected, "{mode:o}");
        }
    }

    fn request(
        operation: DirectOperationCustodyHighWaterOperation,
        current: DirectOperationCustodyHead,
        proposed: Option<DirectOperationCustodyHead>,
        transition: Option<String>,
        nonce: &str,
    ) -> DirectOperationCustodyHighWaterRequestV1 {
        DirectOperationCustodyHighWaterRequestV1::build(
            operation,
            product_route().unwrap(),
            current,
            proposed,
            transition,
            sha256_bytes(nonce.as_bytes()),
        )
        .unwrap()
    }

    #[test]
    fn persisted_prepare_and_commit_survive_restart() {
        let (_temporary, root) = initialized();
        let genesis = DirectOperationCustodyHead::genesis();
        let next = DirectOperationCustodyHead::new(1, sha256_bytes(b"next")).unwrap();
        let transition = transition_sha256(&product_route().unwrap(), &genesis, &next);
        let prepare = request(
            DirectOperationCustodyHighWaterOperation::Prepare,
            genesis.clone(),
            Some(next.clone()),
            Some(transition.clone()),
            "prepare",
        );
        let mut state = load_state(&root).unwrap();
        let response = apply_operation(&mut state, &prepare).unwrap();
        assert_eq!(
            response.disposition,
            DirectOperationCustodyHighWaterDisposition::PreparedExact
        );
        state.pending_exchange = None;
        persist_state(&root, &mut state).unwrap();
        let commit = request(
            DirectOperationCustodyHighWaterOperation::Commit,
            next.clone(),
            Some(next.clone()),
            Some(transition),
            "commit",
        );
        let mut restarted = load_state(&root).unwrap();
        let response = apply_operation(&mut restarted, &commit).unwrap();
        assert_eq!(
            response.disposition,
            DirectOperationCustodyHighWaterDisposition::CommittedExact
        );
        assert_eq!(response.committed_head, next);
    }

    #[test]
    fn response_confirmation_is_durable_and_exactly_replayable() {
        let (_temporary, root) = initialized();
        let request = request(
            DirectOperationCustodyHighWaterOperation::Observe,
            DirectOperationCustodyHead::genesis(),
            None,
            None,
            "observe",
        );
        let response = process_operation(&root, request.clone()).unwrap();
        let confirmation = DirectOperationCustodyHighWaterResponseConfirmationV1::derive(
            &request,
            &response,
            sha256_bytes(b"client-receipt"),
        )
        .unwrap();
        let first = process_confirmation(&root, confirmation.clone()).unwrap();
        let replay = process_confirmation(&root, confirmation).unwrap();
        assert_eq!(first, replay);
        assert_eq!(
            first.disposition,
            DirectOperationCustodyHighWaterConfirmationDisposition::ResponseConfirmedExact
        );
        let state = load_state(&root).unwrap();
        assert!(state.pending_exchange.is_none());
        assert_eq!(state.resolved.len(), 1);
    }

    #[test]
    fn incomplete_publish_and_generation_exhaustion_hold_closed() {
        let (_temporary, root) = initialized();
        File::create(root.join(NEXT_FILE)).unwrap();
        assert!(load_state(&root).is_err());
        fs::remove_file(root.join(NEXT_FILE)).unwrap();
        let mut state = AuthorityState::initial().unwrap();
        state.committed = DirectOperationCustodyHead::new(u64::MAX, sha256_bytes(b"max")).unwrap();
        state.seal().unwrap();
        assert!(state.validate().is_ok());
        let proposed = DirectOperationCustodyHead::new(u64::MAX, sha256_bytes(b"other")).unwrap();
        let denied = DirectOperationCustodyHighWaterRequestV1::build(
            DirectOperationCustodyHighWaterOperation::Prepare,
            product_route().unwrap(),
            state.committed.clone(),
            Some(proposed),
            Some(sha256_bytes(b"transition")),
            sha256_bytes(b"exhausted"),
        );
        assert_eq!(
            denied.unwrap_err(),
            "direct_operation_custody_high_water_generation_overflow"
        );
    }
}
