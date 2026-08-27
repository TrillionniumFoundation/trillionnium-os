//! Fixed-path, source-only root publisher for Direct-operation outer ACK V3.
//!
//! Product code can select neither the directory nor ownership.  Both are
//! derived from the sealed daemon custody snapshot and the generated stable
//! principal registry. The production entry remains unwired from `main`.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd as _, FromRawFd as _, RawFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context as _, Result, anyhow, bail};
use sha2::{Digest as _, Sha256};
use trillionnium_os_types::agent_principal_registry::{
    CODEX_STABLE_PRINCIPAL as CODEX, from_provider_agent_pair,
};
use trillionnium_os_types::direct_operation::DirectOperationAdapter;
use trillionnium_os_types::sha256_bytes;

#[cfg(feature = "p0-launch-package-device-conformance")]
use super::P0BindingPublicationGuarded;
use super::{
    ACK_PUBLISHER_PROVENANCE_SCHEMA, DirectOperationExecutionAuthorityEvidenceV1,
    DirectOperationOuterAckPublisherProvenanceV3, PreparedOuterAckPublication,
    PreparedOuterAckRetirement, PublishedOuterAckInbox, RetiredOuterAckInbox,
    VerifiedOuterAckInboxPublicationProof, VerifiedOuterAckRetirementProof,
};

pub(super) const SOURCE_STATUS: &str =
    "p0_userdebug_fixed_root_outer_ack_v4_publisher_product_authority_held_v2";

const PRODUCT_INBOX_ROOT: &str = "/var/lib/trillionnium/agent-tools/inbox";
const OUTER_ACK_FILE_NAME: &CStr = c"pending-outer-ack-v3.json";
const ACKED_DIRECTORY_NAME: &CStr = c"acked";
const MAX_OUTER_ACK_BYTES: usize = 256 * 1024;
const PRODUCT_PARENT_MODE: u32 = 0o750;
const PUBLISHED_FILE_MODE: u32 = 0o440;
const ACKED_DIRECTORY_MODE: u32 = 0o700;
const OPENAT2_RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const OPENAT2_RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RENAME_NOREPLACE: u32 = 1;
static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u64,
    size: u64,
}

impl FileIdentity {
    fn digest_into(self, hasher: &mut Sha256) {
        hasher.update(self.dev.to_be_bytes());
        hasher.update(self.ino.to_be_bytes());
        hasher.update(self.mode.to_be_bytes());
        hasher.update(self.uid.to_be_bytes());
        hasher.update(self.gid.to_be_bytes());
        hasher.update(self.nlink.to_be_bytes());
        hasher.update(self.size.to_be_bytes());
    }

    fn directory_digest_into(self, hasher: &mut Sha256) {
        hasher.update(self.dev.to_be_bytes());
        hasher.update(self.ino.to_be_bytes());
        hasher.update(self.mode.to_be_bytes());
        hasher.update(self.uid.to_be_bytes());
        hasher.update(self.gid.to_be_bytes());
        hasher.update(self.nlink.to_be_bytes());
    }

    fn stable_directory_digest_into(self, hasher: &mut Sha256) {
        hasher.update(self.dev.to_be_bytes());
        hasher.update(self.ino.to_be_bytes());
        hasher.update(self.mode.to_be_bytes());
        hasher.update(self.uid.to_be_bytes());
        hasher.update(self.gid.to_be_bytes());
    }

    fn same_inode(self, other: Self) -> bool {
        self.dev == other.dev && self.ino == other.ino
    }

    fn same_directory_custody(self, other: Self) -> bool {
        self.dev == other.dev
            && self.ino == other.ino
            && self.mode == other.mode
            && self.uid == other.uid
            && self.gid == other.gid
            && self.nlink == other.nlink
    }
}

#[derive(Debug)]
struct PublisherLocation {
    parent: PathBuf,
    parent_uid: u32,
    parent_gid: u32,
    parent_mode: u32,
    file_uid: u32,
    file_gid: u32,
    archive_uid: u32,
    archive_gid: u32,
}

#[derive(Clone, Debug)]
struct OuterAckPublisherProductAdmission {
    product_descriptor_sha256: String,
    signed_product_measurement_sha256: String,
    avb_partition_digest_sha256: String,
    fsverity_root_digest_sha256: String,
    expected_parent_filesystem_magic: libc::c_long,
    expected_parent_selinux_context_sha256: String,
}

/// Retains the exact parent and published file descriptors until the custody
/// store consumes the proof.  This closes the publish-to-record replacement
/// window even against another root process.
pub(super) struct RetainedOuterAckPublication {
    parent: File,
    file: File,
    parent_identity: FileIdentity,
    file_identity: FileIdentity,
    expected_bytes: Vec<u8>,
    location: PublisherLocation,
    product_admission: Option<OuterAckPublisherProductAdmission>,
}

/// Retains the exact pending parent, root-only archive directory and archived
/// ACK inode until the daemon has durably recorded the retirement proof.
pub(super) struct RetainedOuterAckRetirement {
    parent: File,
    archive: File,
    file: File,
    parent_identity: FileIdentity,
    archive_identity: FileIdentity,
    file_identity: FileIdentity,
    expected_bytes: Vec<u8>,
    archived_leaf_name: CString,
    location: PublisherLocation,
    product_admission: Option<OuterAckPublisherProductAdmission>,
}

/// Non-serialisable product authority placeholder. No production constructor
/// exists in this source slice; future packaging/SELinux/device admission must
/// provide it rather than merely calling a latent fixed-path writer.
#[must_use = "outer-ACK publisher authority must be consumed by the fixed publisher"]
pub(crate) struct VerifiedOuterAckPublisherAuthority {
    admission: OuterAckPublisherProductAdmission,
}

impl VerifiedOuterAckPublisherAuthority {
    fn into_admission(self) -> OuterAckPublisherProductAdmission {
        self.admission
    }
}

/// Private producer token. Its fields are inaccessible outside this module,
/// so the custody parent cannot substitute an arbitrary non-zero source hash.
pub(super) struct PublisherProofToken {
    source_sha256: String,
    publisher_provenance: DirectOperationOuterAckPublisherProvenanceV3,
    retained: RetainedOuterAckPublication,
}

pub(super) struct RetirementProofToken {
    archived_leaf_name: String,
    archived_bytes_sha256: String,
    publisher_provenance: DirectOperationOuterAckPublisherProvenanceV3,
    retirement_custody_source_sha256: String,
    retained: RetainedOuterAckRetirement,
}

impl RetirementProofToken {
    pub(super) fn into_parts(
        self,
    ) -> (
        String,
        String,
        DirectOperationOuterAckPublisherProvenanceV3,
        String,
        RetainedOuterAckRetirement,
    ) {
        (
            self.archived_leaf_name,
            self.archived_bytes_sha256,
            self.publisher_provenance,
            self.retirement_custody_source_sha256,
            self.retained,
        )
    }
}

impl PublisherProofToken {
    pub(super) fn into_parts(
        self,
    ) -> (
        String,
        DirectOperationOuterAckPublisherProvenanceV3,
        RetainedOuterAckPublication,
    ) {
        (self.source_sha256, self.publisher_provenance, self.retained)
    }
}

impl RetainedOuterAckPublication {
    pub(super) fn revalidate(&mut self) -> Result<()> {
        let parent_now = identity(self.parent.as_raw_fd())?;
        validate_directory_identity(
            parent_now,
            self.location.parent_uid,
            self.location.parent_gid,
            self.location.parent_mode,
        )?;
        if !parent_now.same_directory_custody(self.parent_identity) {
            bail!("direct_operation_outer_ack_parent_identity_changed");
        }
        let path_parent = open_parent(&self.location.parent)?;
        let path_parent_identity = identity(path_parent.as_raw_fd())?;
        validate_directory_identity(
            path_parent_identity,
            self.location.parent_uid,
            self.location.parent_gid,
            self.location.parent_mode,
        )?;
        if !path_parent_identity.same_directory_custody(self.parent_identity) {
            bail!("direct_operation_outer_ack_parent_path_rebound");
        }
        if let Some(admission) = &self.product_admission {
            verify_product_parent_admission(&self.parent, admission)?;
        }
        let file_now = identity(self.file.as_raw_fd())?;
        validate_published_identity(
            file_now,
            self.location.file_uid,
            self.location.file_gid,
            self.expected_bytes.len(),
        )?;
        if file_now != self.file_identity {
            bail!("direct_operation_outer_ack_open_file_identity_changed");
        }
        let named = open_named_readonly(self.parent.as_raw_fd(), OUTER_ACK_FILE_NAME)?;
        let named_identity = identity(named.as_raw_fd())?;
        if named_identity != self.file_identity {
            bail!("direct_operation_outer_ack_named_file_replaced");
        }
        let bytes = read_exact_bounded(&named, MAX_OUTER_ACK_BYTES)?;
        if bytes != self.expected_bytes {
            bail!("direct_operation_outer_ack_named_bytes_changed");
        }
        Ok(())
    }
}

impl RetainedOuterAckRetirement {
    pub(super) fn revalidate(&mut self) -> Result<()> {
        let parent_now = identity(self.parent.as_raw_fd())?;
        validate_directory_identity(
            parent_now,
            self.location.parent_uid,
            self.location.parent_gid,
            self.location.parent_mode,
        )?;
        if !parent_now.same_directory_custody(self.parent_identity) {
            bail!("direct_operation_outer_ack_retirement_parent_identity_changed");
        }
        let path_parent = open_parent(&self.location.parent)?;
        if !identity(path_parent.as_raw_fd())?.same_directory_custody(self.parent_identity) {
            bail!("direct_operation_outer_ack_retirement_parent_path_rebound");
        }
        if let Some(admission) = &self.product_admission {
            verify_product_parent_admission(&self.parent, admission)?;
        }
        if open_named_optional(self.parent.as_raw_fd(), OUTER_ACK_FILE_NAME)?.is_some() {
            bail!("direct_operation_outer_ack_retirement_pending_reappeared");
        }
        let archive_now = identity(self.archive.as_raw_fd())?;
        validate_directory_identity(
            archive_now,
            self.location.archive_uid,
            self.location.archive_gid,
            ACKED_DIRECTORY_MODE,
        )?;
        if !archive_now.same_directory_custody(self.archive_identity) {
            bail!("direct_operation_outer_ack_archive_identity_changed");
        }
        let named_archive = open_directory_at(self.parent.as_raw_fd(), ACKED_DIRECTORY_NAME)?;
        if !identity(named_archive.as_raw_fd())?.same_directory_custody(self.archive_identity) {
            bail!("direct_operation_outer_ack_archive_path_rebound");
        }
        let file_now = validate_exact_named(
            &self.file,
            &self.expected_bytes,
            self.location.file_uid,
            self.location.file_gid,
        )?;
        if file_now != self.file_identity {
            bail!("direct_operation_outer_ack_archived_open_inode_changed");
        }
        let named =
            open_named_readonly(self.archive.as_raw_fd(), self.archived_leaf_name.as_c_str())?;
        if validate_exact_named(
            &named,
            &self.expected_bytes,
            self.location.file_uid,
            self.location.file_gid,
        )? != self.file_identity
        {
            bail!("direct_operation_outer_ack_archived_named_inode_changed");
        }
        Ok(())
    }
}

/// Fixed publisher instance.  A parent-fsync uncertainty fail-stops this
/// instance; a new process may reopen and reconcile the exact named bytes.
pub(crate) struct FixedOuterAckInboxPublisher {
    durability_uncertain: bool,
    product_admission: Option<OuterAckPublisherProductAdmission>,
    p0_userdebug_conformance: bool,
    #[cfg(test)]
    test_location: Option<PublisherLocation>,
    #[cfg(test)]
    test_authority_evidence: Option<DirectOperationExecutionAuthorityEvidenceV1>,
    #[cfg(test)]
    fault_once: Option<TestPublishFault>,
}

impl FixedOuterAckInboxPublisher {
    pub(crate) fn from_verified_product_authority(
        authority: VerifiedOuterAckPublisherAuthority,
    ) -> Self {
        Self {
            durability_uncertain: false,
            product_admission: Some(authority.into_admission()),
            p0_userdebug_conformance: false,
            #[cfg(test)]
            test_location: None,
            #[cfg(test)]
            test_authority_evidence: None,
            #[cfg(test)]
            fault_once: None,
        }
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    pub(crate) fn from_p0_userdebug_conformance() -> Result<Self> {
        if option_env!("TRILLIONNIUM_P01_CONFORMANCE_BUILD_VARIANT") != Some("userdebug") {
            bail!("direct_operation_outer_ack_p0_userdebug_compiled_variant_denied");
        }
        Ok(Self {
            durability_uncertain: false,
            product_admission: None,
            p0_userdebug_conformance: true,
            #[cfg(test)]
            test_location: None,
            #[cfg(test)]
            test_authority_evidence: None,
            #[cfg(test)]
            fault_once: None,
        })
    }

    pub(crate) fn publication_durability_uncertain(&self) -> bool {
        self.durability_uncertain
    }

    pub(crate) fn publish(
        &mut self,
        prepared: PreparedOuterAckPublication,
    ) -> Result<PublishedOuterAckInbox> {
        if self.durability_uncertain {
            bail!("direct_operation_outer_ack_publisher_commit_unknown");
        }
        validate_prepared_identity(&prepared)?;
        let location = self.location(&prepared)?;
        let mut bytes = serde_json::to_vec(&prepared.inbox)
            .context("direct_operation_outer_ack_encode_failed")?;
        bytes.push(b'\n');
        if bytes.len() > MAX_OUTER_ACK_BYTES {
            bail!("direct_operation_outer_ack_canonical_bytes_oversized");
        }
        let decoded = serde_json::from_slice::<
            trillionnium_os_types::direct_operation::DirectOperationOuterAckInboxV3,
        >(&bytes[..bytes.len() - 1])
        .context("direct_operation_outer_ack_canonical_readback_invalid")?;
        if decoded != prepared.inbox {
            bail!("direct_operation_outer_ack_canonical_roundtrip_drift");
        }

        let parent = open_parent(&location.parent)?;
        let parent_identity = identity(parent.as_raw_fd())?;
        validate_directory_identity(
            parent_identity,
            location.parent_uid,
            location.parent_gid,
            location.parent_mode,
        )?;
        let publisher_provenance = if let Some(admission) = &self.product_admission {
            verify_product_parent_admission(&parent, admission)?
        } else if self.p0_userdebug_conformance {
            verify_p0_userdebug_parent_admission(&parent, &prepared)?
        } else {
            source_only_test_publisher_provenance(
                #[cfg(test)]
                self.test_authority_evidence.clone(),
            )?
        };
        let product_parent_provenance_sha256 = publisher_provenance_digest(&publisher_provenance);

        let (file, file_identity) = if let Some(existing) =
            open_named_optional(parent.as_raw_fd(), OUTER_ACK_FILE_NAME)?
        {
            let file_identity =
                validate_exact_named(&existing, &bytes, location.file_uid, location.file_gid)?;
            existing
                .sync_all()
                .context("direct_operation_outer_ack_existing_file_fsync_failed")?;
            parent
                .sync_all()
                .context("direct_operation_outer_ack_existing_parent_fsync_failed")?;
            (existing, file_identity)
        } else {
            match self.publish_new(&parent, &location, &bytes)? {
                PublishNewOutcome::Installed(file, identity) => (file, identity),
                PublishNewOutcome::LostRace => {
                    let existing = open_named_readonly(parent.as_raw_fd(), OUTER_ACK_FILE_NAME)?;
                    let file_identity = validate_exact_named(
                        &existing,
                        &bytes,
                        location.file_uid,
                        location.file_gid,
                    )?;
                    existing
                        .sync_all()
                        .context("direct_operation_outer_ack_race_file_fsync_failed")?;
                    parent
                        .sync_all()
                        .context("direct_operation_outer_ack_race_parent_fsync_failed")?;
                    (existing, file_identity)
                }
            }
        };

        let parent_after = identity(parent.as_raw_fd())?;
        if !parent_after.same_directory_custody(parent_identity) {
            self.durability_uncertain = true;
            bail!("direct_operation_outer_ack_parent_changed_after_publish");
        }
        let path_parent = open_parent(&location.parent)?;
        let path_parent_identity = identity(path_parent.as_raw_fd())?;
        if !path_parent_identity.same_directory_custody(parent_after) {
            self.durability_uncertain = true;
            bail!("direct_operation_outer_ack_parent_path_rebound_after_publish");
        }
        let named = open_named_readonly(parent.as_raw_fd(), OUTER_ACK_FILE_NAME)?;
        let named_identity =
            validate_exact_named(&named, &bytes, location.file_uid, location.file_gid)?;
        if !named_identity.same_inode(file_identity) {
            self.durability_uncertain = true;
            bail!("direct_operation_outer_ack_named_inode_changed_after_publish");
        }
        drop(named);

        let source_sha256 = publication_source_digest(
            &prepared,
            &bytes,
            parent_after,
            file_identity,
            &product_parent_provenance_sha256,
        );
        let retained = RetainedOuterAckPublication {
            parent,
            file,
            parent_identity: parent_after,
            file_identity,
            expected_bytes: bytes,
            location,
            product_admission: self.product_admission.clone(),
        };
        let verified = VerifiedOuterAckInboxPublicationProof::from_fixed_publisher(
            &prepared,
            PublisherProofToken {
                source_sha256,
                publisher_provenance,
                retained,
            },
        )?;
        Ok(PublishedOuterAckInbox {
            custody_head: prepared.custody_head,
            binding_sha256: prepared.binding_sha256,
            adapter: prepared.adapter,
            verified,
        })
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    pub(crate) fn publish_p0(
        &mut self,
        guarded: P0BindingPublicationGuarded<PreparedOuterAckPublication>,
    ) -> Result<P0BindingPublicationGuarded<PublishedOuterAckInbox>> {
        let (publication, prepared) = guarded.into_parts();
        publication.validate_for_phase(
            &prepared.custody_head,
            &prepared.binding_sha256,
            prepared.adapter,
        )?;
        let published = self.publish(prepared)?;
        publication.validate_for_phase(
            &published.custody_head,
            &published.binding_sha256,
            published.adapter,
        )?;
        Ok(P0BindingPublicationGuarded::new(publication, published))
    }

    /// After the exact Android confirmation is durable in daemon custody,
    /// atomically retire the fixed pending inbox into a deterministic root-only
    /// per-intent archive.  This is a namespace move, never a delete-first
    /// cleanup, so a crash always leaves at least one exact durable copy.
    pub(crate) fn retire(
        &mut self,
        prepared: PreparedOuterAckRetirement,
    ) -> Result<RetiredOuterAckInbox> {
        if self.durability_uncertain {
            bail!("direct_operation_outer_ack_publisher_commit_unknown");
        }
        validate_retirement_prepared_identity(&prepared)?;
        let location = self.location_for_identity(
            &prepared.provider_id,
            &prepared.agent_id,
            prepared.adapter,
        )?;
        let mut bytes = serde_json::to_vec(&prepared.inbox)
            .context("direct_operation_outer_ack_retirement_encode_failed")?;
        bytes.push(b'\n');
        if bytes.len() > MAX_OUTER_ACK_BYTES {
            bail!("direct_operation_outer_ack_retirement_bytes_oversized");
        }
        let archived_leaf_string = format!("acked-{}.json", prepared.ack_intent_sha256);
        let archived_leaf_name = CString::new(archived_leaf_string.clone())
            .context("direct_operation_outer_ack_archive_leaf_invalid")?;

        let parent = open_parent(&location.parent)?;
        let initial_parent_identity = identity(parent.as_raw_fd())?;
        validate_directory_identity(
            initial_parent_identity,
            location.parent_uid,
            location.parent_gid,
            location.parent_mode,
        )?;
        let publisher_provenance = if let Some(admission) = &self.product_admission {
            verify_product_parent_admission(&parent, admission)?
        } else if self.p0_userdebug_conformance {
            verify_p0_userdebug_retirement_parent_admission(&parent, &prepared)?
        } else {
            source_only_test_publisher_provenance(
                #[cfg(test)]
                self.test_authority_evidence.clone(),
            )?
        };
        let product_parent_provenance_sha256 = publisher_provenance_digest(&publisher_provenance);
        let (archive, archive_identity) = self.open_or_create_archive(&parent, &location)?;
        let parent_identity = identity(parent.as_raw_fd())?;
        validate_directory_identity(
            parent_identity,
            location.parent_uid,
            location.parent_gid,
            location.parent_mode,
        )?;
        if !parent_identity.same_inode(initial_parent_identity) {
            self.durability_uncertain = true;
            bail!("direct_operation_outer_ack_parent_rebound_during_archive_open");
        }

        let pending = open_named_optional(parent.as_raw_fd(), OUTER_ACK_FILE_NAME)?;
        let archived = open_named_optional(archive.as_raw_fd(), archived_leaf_name.as_c_str())?;
        let (file, file_identity, namespace_mutated) = match (pending, archived) {
            (Some(pending), None) => {
                let pending_identity =
                    validate_exact_named(&pending, &bytes, location.file_uid, location.file_gid)?;
                pending
                    .sync_all()
                    .context("direct_operation_outer_ack_pending_fsync_failed")?;
                self.durability_uncertain = true;
                match rename_noreplace_between(
                    parent.as_raw_fd(),
                    OUTER_ACK_FILE_NAME,
                    archive.as_raw_fd(),
                    archived_leaf_name.as_c_str(),
                ) {
                    Ok(()) => (pending, pending_identity, true),
                    Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {
                        let winner = open_named_readonly(
                            archive.as_raw_fd(),
                            archived_leaf_name.as_c_str(),
                        )?;
                        let winner_identity = validate_exact_named(
                            &winner,
                            &bytes,
                            location.file_uid,
                            location.file_gid,
                        )?;
                        unlink_exact_named(&parent, OUTER_ACK_FILE_NAME, pending_identity)?;
                        (winner, winner_identity, true)
                    }
                    Err(error) => {
                        self.durability_uncertain = true;
                        return Err(error).context(
                            "direct_operation_outer_ack_retirement_rename_commit_unknown",
                        );
                    }
                }
            }
            (Some(pending), Some(archived)) => {
                let pending_identity =
                    validate_exact_named(&pending, &bytes, location.file_uid, location.file_gid)?;
                let archived_identity =
                    validate_exact_named(&archived, &bytes, location.file_uid, location.file_gid)?;
                if pending_identity.same_inode(archived_identity) {
                    bail!("direct_operation_outer_ack_archive_pending_inode_alias_denied");
                }
                archived
                    .sync_all()
                    .context("direct_operation_outer_ack_archived_existing_fsync_failed")?;
                self.durability_uncertain = true;
                unlink_exact_named(&parent, OUTER_ACK_FILE_NAME, pending_identity)?;
                (archived, archived_identity, true)
            }
            (None, Some(archived)) => {
                let archived_identity =
                    validate_exact_named(&archived, &bytes, location.file_uid, location.file_gid)?;
                archived
                    .sync_all()
                    .context("direct_operation_outer_ack_archived_reconcile_fsync_failed")?;
                (archived, archived_identity, false)
            }
            (None, None) => {
                bail!("direct_operation_outer_ack_retirement_source_and_archive_absent")
            }
        };

        // Once the pending namespace has moved or been removed, every failure
        // is commit-unknown for this process.  A fresh process can reconcile
        // only the exact deterministic archive bytes.
        #[cfg(test)]
        let retirement_parent_fsync_fault =
            self.take_fault(TestPublishFault::RetirementParentFsync);
        #[cfg(not(test))]
        let retirement_parent_fsync_fault = false;
        let durable = (|| -> Result<()> {
            file.sync_all()
                .context("direct_operation_outer_ack_retirement_file_fsync_failed")?;
            archive
                .sync_all()
                .context("direct_operation_outer_ack_archive_directory_fsync_failed")?;
            if retirement_parent_fsync_fault {
                bail!("direct_operation_outer_ack_retirement_parent_fsync_test_fault");
            }
            parent
                .sync_all()
                .context("direct_operation_outer_ack_retirement_parent_fsync_failed")?;
            if open_named_optional(parent.as_raw_fd(), OUTER_ACK_FILE_NAME)?.is_some() {
                bail!("direct_operation_outer_ack_pending_survived_retirement");
            }
            let named = open_named_readonly(archive.as_raw_fd(), archived_leaf_name.as_c_str())?;
            let named_identity =
                validate_exact_named(&named, &bytes, location.file_uid, location.file_gid)?;
            if named_identity != file_identity {
                bail!("direct_operation_outer_ack_retirement_inode_drift");
            }
            let path_parent = open_parent(&location.parent)?;
            if !identity(path_parent.as_raw_fd())?.same_directory_custody(parent_identity) {
                bail!("direct_operation_outer_ack_retirement_parent_path_rebound");
            }
            Ok(())
        })();
        if let Err(error) = durable {
            if namespace_mutated {
                self.durability_uncertain = true;
            }
            return Err(error);
        }
        self.durability_uncertain = false;

        let archived_bytes_sha256 = sha256_bytes(&bytes);
        let retirement_custody_source_sha256 = retirement_source_digest(
            &prepared,
            &archived_bytes_sha256,
            parent_identity,
            archive_identity,
            file_identity,
            &product_parent_provenance_sha256,
        );
        let retained = RetainedOuterAckRetirement {
            parent,
            archive,
            file,
            parent_identity,
            archive_identity,
            file_identity,
            expected_bytes: bytes,
            archived_leaf_name,
            location,
            product_admission: self.product_admission.clone(),
        };
        let verified = VerifiedOuterAckRetirementProof::from_fixed_publisher(
            &prepared,
            RetirementProofToken {
                archived_leaf_name: archived_leaf_string,
                archived_bytes_sha256,
                publisher_provenance,
                retirement_custody_source_sha256,
                retained,
            },
        )?;
        Ok(RetiredOuterAckInbox {
            custody_head: prepared.custody_head,
            binding_sha256: prepared.binding_sha256,
            adapter: prepared.adapter,
            verified,
        })
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    pub(crate) fn retire_p0(
        &mut self,
        guarded: P0BindingPublicationGuarded<PreparedOuterAckRetirement>,
    ) -> Result<P0BindingPublicationGuarded<RetiredOuterAckInbox>> {
        let (publication, prepared) = guarded.into_parts();
        publication.validate_for_phase(
            &prepared.custody_head,
            &prepared.binding_sha256,
            prepared.adapter,
        )?;
        let retired = self.retire(prepared)?;
        publication.validate_for_phase(
            &retired.custody_head,
            &retired.binding_sha256,
            retired.adapter,
        )?;
        Ok(P0BindingPublicationGuarded::new(publication, retired))
    }

    fn open_or_create_archive(
        &mut self,
        parent: &File,
        location: &PublisherLocation,
    ) -> Result<(File, FileIdentity)> {
        let created = match mkdir_directory_at(parent.as_raw_fd(), ACKED_DIRECTORY_NAME) {
            Ok(()) => true,
            Err(error) if error.raw_os_error() == Some(libc::EEXIST) => false,
            Err(error) => {
                return Err(error).context("direct_operation_outer_ack_archive_mkdir_failed");
            }
        };
        let archive = open_directory_at(parent.as_raw_fd(), ACKED_DIRECTORY_NAME)?;
        if created {
            self.durability_uncertain = true;
            let created_durable = (|| -> Result<()> {
                set_owner_and_mode(
                    &archive,
                    location.archive_uid,
                    location.archive_gid,
                    ACKED_DIRECTORY_MODE,
                )?;
                archive
                    .sync_all()
                    .context("direct_operation_outer_ack_new_archive_fsync_failed")?;
                parent
                    .sync_all()
                    .context("direct_operation_outer_ack_new_archive_parent_fsync_unknown")?;
                Ok(())
            })();
            created_durable?;
            self.durability_uncertain = false;
        }
        let archive_identity = identity(archive.as_raw_fd())?;
        validate_directory_identity(
            archive_identity,
            location.archive_uid,
            location.archive_gid,
            ACKED_DIRECTORY_MODE,
        )?;
        Ok((archive, archive_identity))
    }

    fn location(&self, prepared: &PreparedOuterAckPublication) -> Result<PublisherLocation> {
        self.location_for_identity(&prepared.provider_id, &prepared.agent_id, prepared.adapter)
    }

    fn location_for_identity(
        &self,
        provider_id: &str,
        agent_id: &str,
        selected_adapter: DirectOperationAdapter,
    ) -> Result<PublisherLocation> {
        #[cfg(test)]
        if let Some(location) = &self.test_location {
            return Ok(PublisherLocation {
                parent: location.parent.clone(),
                parent_uid: location.parent_uid,
                parent_gid: location.parent_gid,
                parent_mode: location.parent_mode,
                file_uid: location.file_uid,
                file_gid: location.file_gid,
                archive_uid: location.archive_uid,
                archive_gid: location.archive_gid,
            });
        }

        let descriptor = from_provider_agent_pair(provider_id, agent_id)
            .ok_or_else(|| anyhow!("direct_operation_outer_ack_descriptor_identity_denied"))?;
        let provider = if descriptor == &CODEX {
            "codex"
        } else {
            bail!("direct_operation_outer_ack_descriptor_identity_denied");
        };
        let adapter = match selected_adapter {
            DirectOperationAdapter::SystemApi => "system-api",
            DirectOperationAdapter::Accessibility => "accessibility",
        };
        Ok(PublisherLocation {
            parent: Path::new(PRODUCT_INBOX_ROOT).join(provider).join(adapter),
            parent_uid: 0,
            parent_gid: descriptor.gid,
            parent_mode: PRODUCT_PARENT_MODE,
            file_uid: 0,
            file_gid: descriptor.gid,
            archive_uid: 0,
            archive_gid: 0,
        })
    }

    fn publish_new(
        &mut self,
        parent: &File,
        location: &PublisherLocation,
        bytes: &[u8],
    ) -> Result<PublishNewOutcome> {
        let temporary_name = temporary_name()?;
        let mut temporary = open_new_temporary(parent.as_raw_fd(), &temporary_name)?;
        let before_rename = (|| -> Result<FileIdentity> {
            set_owner_and_mode(
                &temporary,
                location.file_uid,
                location.file_gid,
                PUBLISHED_FILE_MODE,
            )?;
            #[cfg(test)]
            if self.take_fault(TestPublishFault::PartialWrite) {
                let partial = bytes.len().saturating_div(2).max(1);
                temporary.write_all(&bytes[..partial])?;
                temporary.sync_all()?;
                bail!("direct_operation_outer_ack_partial_write_test_fault");
            }
            temporary.write_all(bytes)?;
            #[cfg(test)]
            if self.take_fault(TestPublishFault::FileFsync) {
                bail!("direct_operation_outer_ack_file_fsync_test_fault");
            }
            temporary
                .sync_all()
                .context("direct_operation_outer_ack_file_fsync_failed")?;
            let temporary_identity =
                validate_exact_named(&temporary, bytes, location.file_uid, location.file_gid)?;
            Ok(temporary_identity)
        })();
        let temporary_identity = match before_rename {
            Ok(identity) => identity,
            Err(error) => {
                cleanup_unpublished_temporary(
                    parent,
                    &temporary_name,
                    &temporary,
                    &mut self.durability_uncertain,
                )?;
                return Err(error);
            }
        };

        #[cfg(test)]
        if self.take_fault(TestPublishFault::ExactNoReplaceRace) {
            install_test_race_winner(parent, location, bytes)?;
        }
        #[cfg(test)]
        if self.take_fault(TestPublishFault::DriftNoReplaceRace) {
            install_test_race_winner(parent, location, b"racing-drift\n")?;
        }

        match rename_noreplace(parent.as_raw_fd(), &temporary_name, OUTER_ACK_FILE_NAME) {
            Ok(()) => {}
            Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {
                cleanup_unpublished_temporary(
                    parent,
                    &temporary_name,
                    &temporary,
                    &mut self.durability_uncertain,
                )?;
                return Ok(PublishNewOutcome::LostRace);
            }
            Err(error) => {
                cleanup_unpublished_temporary(
                    parent,
                    &temporary_name,
                    &temporary,
                    &mut self.durability_uncertain,
                )?;
                return Err(error).context("direct_operation_outer_ack_rename_noreplace_failed");
            }
        }

        #[cfg(test)]
        if self.take_fault(TestPublishFault::ParentFsync) {
            self.durability_uncertain = true;
            bail!("direct_operation_outer_ack_parent_fsync_commit_unknown_test_fault");
        }
        if let Err(error) = parent.sync_all() {
            self.durability_uncertain = true;
            return Err(error).context("direct_operation_outer_ack_parent_fsync_commit_unknown");
        }
        let named = open_named_readonly(parent.as_raw_fd(), OUTER_ACK_FILE_NAME)?;
        let named_identity =
            validate_exact_named(&named, bytes, location.file_uid, location.file_gid)?;
        if named_identity != temporary_identity {
            self.durability_uncertain = true;
            bail!("direct_operation_outer_ack_installed_inode_drift");
        }
        Ok(PublishNewOutcome::Installed(named, named_identity))
    }

    #[cfg(test)]
    pub(super) fn for_test(
        parent: PathBuf,
        parent_uid: u32,
        parent_gid: u32,
        parent_mode: u32,
        file_uid: u32,
        file_gid: u32,
    ) -> Self {
        Self {
            durability_uncertain: false,
            product_admission: None,
            p0_userdebug_conformance: false,
            test_location: Some(PublisherLocation {
                parent,
                parent_uid,
                parent_gid,
                parent_mode,
                file_uid,
                file_gid,
                archive_uid: file_uid,
                archive_gid: file_gid,
            }),
            test_authority_evidence: None,
            fault_once: None,
        }
    }

    #[cfg(test)]
    pub(super) fn use_test_authority_evidence(
        &mut self,
        authority_evidence: DirectOperationExecutionAuthorityEvidenceV1,
    ) {
        self.test_authority_evidence = Some(authority_evidence);
    }

    #[cfg(test)]
    pub(super) fn fail_once(&mut self, fault: TestPublishFault) {
        self.fault_once = Some(fault);
    }

    #[cfg(test)]
    fn take_fault(&mut self, expected: TestPublishFault) -> bool {
        if self.fault_once == Some(expected) {
            self.fault_once = None;
            true
        } else {
            false
        }
    }
}

enum PublishNewOutcome {
    Installed(File, FileIdentity),
    LostRace,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TestPublishFault {
    PartialWrite,
    FileFsync,
    ParentFsync,
    ExactNoReplaceRace,
    DriftNoReplaceRace,
    RetirementParentFsync,
}

#[cfg(test)]
fn install_test_race_winner(
    parent: &File,
    location: &PublisherLocation,
    bytes: &[u8],
) -> Result<()> {
    let mut winner = open_new_temporary(parent.as_raw_fd(), OUTER_ACK_FILE_NAME)?;
    set_owner_and_mode(
        &winner,
        location.file_uid,
        location.file_gid,
        PUBLISHED_FILE_MODE,
    )?;
    winner.write_all(bytes)?;
    winner.sync_all()?;
    parent.sync_all()?;
    Ok(())
}

fn validate_prepared_identity(prepared: &PreparedOuterAckPublication) -> Result<()> {
    prepared
        .inbox
        .validate()
        .map_err(|error| anyhow!(error.to_string()))?;
    let acknowledgement = &prepared.inbox.acknowledgement;
    if acknowledgement.adapter != prepared.adapter
        || acknowledgement.binding_sha256 != prepared.binding_sha256
        || acknowledgement.provider_id != prepared.provider_id
        || acknowledgement.agent_id != prepared.agent_id
        || from_provider_agent_pair(&prepared.provider_id, &prepared.agent_id).is_none()
        || prepared.custody_head.generation == 0
        || prepared.custody_head.store_sha256.len() != 64
        || prepared.ack_intent_sha256.len() != 64
    {
        bail!("direct_operation_outer_ack_prepared_identity_denied");
    }
    Ok(())
}

fn validate_retirement_prepared_identity(prepared: &PreparedOuterAckRetirement) -> Result<()> {
    prepared
        .inbox
        .validate()
        .map_err(|error| anyhow!(error.to_string()))?;
    let acknowledgement = &prepared.inbox.acknowledgement;
    if acknowledgement.adapter != prepared.adapter
        || acknowledgement.binding_sha256 != prepared.binding_sha256
        || acknowledgement.provider_id != prepared.provider_id
        || acknowledgement.agent_id != prepared.agent_id
        || from_provider_agent_pair(&prepared.provider_id, &prepared.agent_id).is_none()
        || prepared.custody_head.generation == 0
        || !valid_nonzero_digest(&prepared.custody_head.store_sha256)
        || !valid_nonzero_digest(&prepared.ack_intent_sha256)
        || !valid_nonzero_digest(&prepared.launch_id_sha256)
        || prepared.outer_ack_inbox_publication.adapter != prepared.adapter
        || prepared.outer_ack_inbox_publication.binding_sha256 != prepared.binding_sha256
        || prepared.outer_ack_inbox_publication.ack_intent_sha256 != prepared.ack_intent_sha256
        || prepared.android_backend_ack_confirmation.adapter != prepared.adapter
        || prepared.android_backend_ack_confirmation.binding_sha256 != prepared.binding_sha256
        || prepared.android_backend_ack_confirmation.ack_intent_sha256 != prepared.ack_intent_sha256
        || prepared.android_backend_ack_confirmation.launch_id_sha256 != prepared.launch_id_sha256
        || prepared
            .android_backend_ack_confirmation
            .acknowledgement_sha256
            != prepared.inbox.acknowledgement_sha256
        || prepared
            .android_backend_ack_confirmation
            .authenticated_ack_chain_sha256
            != prepared.inbox.chain_step.authenticated_ack_chain_sha256
        || prepared
            .android_backend_ack_confirmation
            .launch_receipt_sha256
            != prepared
                .android_backend_ack_confirmation
                .android_confirmation_source_sha256
        || !valid_nonzero_digest(
            &prepared
                .android_backend_ack_confirmation
                .launch_receipt_sha256,
        )
    {
        bail!("direct_operation_outer_ack_retirement_prepared_identity_denied");
    }
    Ok(())
}

fn publication_source_digest(
    prepared: &PreparedOuterAckPublication,
    bytes: &[u8],
    parent: FileIdentity,
    file: FileIdentity,
    product_parent_provenance_sha256: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"trillionnium.direct-operation-fixed-outer-ack-publisher.v1\0");
    // The result token carries the affine custody head separately.  The
    // persisted publication proof must remain identical when the same named
    // inode is reconciled after that proof was already durably recorded.
    hash_field(&mut hasher, prepared.provider_id.as_bytes());
    hash_field(&mut hasher, prepared.agent_id.as_bytes());
    hash_field(&mut hasher, prepared.adapter.adapter_id().as_bytes());
    hash_field(&mut hasher, prepared.binding_sha256.as_bytes());
    hash_field(&mut hasher, prepared.ack_intent_sha256.as_bytes());
    hash_field(&mut hasher, sha256_bytes(bytes).as_bytes());
    hash_field(&mut hasher, product_parent_provenance_sha256.as_bytes());
    // Directory byte size changes during the first publication and can change
    // for unrelated entries.  It is neither a stable identity field nor a
    // custody boundary.  Keep the retained inode/owner/mode/link identity.
    parent.directory_digest_into(&mut hasher);
    file.digest_into(&mut hasher);
    format!("{:x}", hasher.finalize())
}

fn retirement_source_digest(
    prepared: &PreparedOuterAckRetirement,
    archived_bytes_sha256: &str,
    parent: FileIdentity,
    archive: FileIdentity,
    file: FileIdentity,
    product_parent_provenance_sha256: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"trillionnium.direct-operation-fixed-outer-ack-retirement.v1\0");
    for value in [
        prepared.provider_id.as_str(),
        prepared.agent_id.as_str(),
        prepared.adapter.adapter_id(),
        prepared.binding_sha256.as_str(),
        prepared.ack_intent_sha256.as_str(),
        prepared.launch_id_sha256.as_str(),
        prepared
            .android_backend_ack_confirmation
            .launch_receipt_sha256
            .as_str(),
        archived_bytes_sha256,
        product_parent_provenance_sha256,
    ] {
        hash_field(&mut hasher, value.as_bytes());
    }
    parent.directory_digest_into(&mut hasher);
    archive.directory_digest_into(&mut hasher);
    file.digest_into(&mut hasher);
    format!("{:x}", hasher.finalize())
}

fn verify_product_parent_admission(
    parent: &File,
    admission: &OuterAckPublisherProductAdmission,
) -> Result<DirectOperationOuterAckPublisherProvenanceV3> {
    if !valid_nonzero_digest(&admission.product_descriptor_sha256)
        || !valid_nonzero_digest(&admission.signed_product_measurement_sha256)
        || !valid_nonzero_digest(&admission.avb_partition_digest_sha256)
        || !valid_nonzero_digest(&admission.fsverity_root_digest_sha256)
        || !valid_nonzero_digest(&admission.expected_parent_selinux_context_sha256)
    {
        bail!("direct_operation_outer_ack_product_admission_denied");
    }
    let mut filesystem = MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: filesystem is writable output storage for one retained dirfd.
    if unsafe { libc::fstatfs(parent.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("direct_operation_outer_ack_parent_fstatfs_failed");
    }
    let filesystem = unsafe { filesystem.assume_init() };
    if filesystem.f_type != admission.expected_parent_filesystem_magic {
        bail!("direct_operation_outer_ack_parent_filesystem_drift");
    }
    let mut context = vec![0_u8; 4096];
    // SAFETY: context is writable and the xattr name is fixed.
    let count = unsafe {
        libc::fgetxattr(
            parent.as_raw_fd(),
            c"security.selinux".as_ptr(),
            context.as_mut_ptr().cast(),
            context.len(),
        )
    };
    if count <= 0 {
        return Err(std::io::Error::last_os_error())
            .context("direct_operation_outer_ack_parent_selinux_xattr_unavailable");
    }
    context.truncate(count as usize);
    if sha256_bytes(&context) != admission.expected_parent_selinux_context_sha256 {
        bail!("direct_operation_outer_ack_parent_selinux_context_drift");
    }
    let mut filesystem_identity = Sha256::new();
    filesystem_identity.update(b"trillionnium.direct-operation-outer-ack-parent-filesystem.v1\0");
    filesystem_identity.update(filesystem.f_type.to_be_bytes());
    identity(parent.as_raw_fd())?.stable_directory_digest_into(&mut filesystem_identity);
    let provenance = DirectOperationOuterAckPublisherProvenanceV3 {
        schema: ACK_PUBLISHER_PROVENANCE_SCHEMA.to_string(),
        authority_evidence: DirectOperationExecutionAuthorityEvidenceV1::SignedProduct {
            product_descriptor_sha256: admission.product_descriptor_sha256.clone(),
            signed_product_measurement_sha256: admission.signed_product_measurement_sha256.clone(),
            avb_partition_digest_sha256: admission.avb_partition_digest_sha256.clone(),
        },
        fsverity_root_digest_sha256: Some(admission.fsverity_root_digest_sha256.clone()),
        parent_filesystem_identity_sha256: format!("{:x}", filesystem_identity.finalize()),
        parent_selinux_context_sha256: admission.expected_parent_selinux_context_sha256.clone(),
    };
    provenance.validate()?;
    Ok(provenance)
}

#[cfg(feature = "p0-launch-package-device-conformance")]
fn verify_p0_userdebug_parent_admission(
    parent: &File,
    prepared: &PreparedOuterAckPublication,
) -> Result<DirectOperationOuterAckPublisherProvenanceV3> {
    verify_p0_userdebug_parent_admission_for_identity(
        parent,
        &prepared.provider_id,
        prepared.adapter,
    )
}

#[cfg(not(feature = "p0-launch-package-device-conformance"))]
fn verify_p0_userdebug_parent_admission(
    _parent: &File,
    _prepared: &PreparedOuterAckPublication,
) -> Result<DirectOperationOuterAckPublisherProvenanceV3> {
    bail!("direct_operation_outer_ack_p0_userdebug_feature_absent")
}

#[cfg(feature = "p0-launch-package-device-conformance")]
fn verify_p0_userdebug_retirement_parent_admission(
    parent: &File,
    prepared: &PreparedOuterAckRetirement,
) -> Result<DirectOperationOuterAckPublisherProvenanceV3> {
    verify_p0_userdebug_parent_admission_for_identity(
        parent,
        &prepared.provider_id,
        prepared.adapter,
    )
}

#[cfg(not(feature = "p0-launch-package-device-conformance"))]
fn verify_p0_userdebug_retirement_parent_admission(
    _parent: &File,
    _prepared: &PreparedOuterAckRetirement,
) -> Result<DirectOperationOuterAckPublisherProvenanceV3> {
    bail!("direct_operation_outer_ack_p0_userdebug_feature_absent")
}

#[cfg(feature = "p0-launch-package-device-conformance")]
fn verify_p0_userdebug_parent_admission_for_identity(
    parent: &File,
    provider_id: &str,
    adapter: DirectOperationAdapter,
) -> Result<DirectOperationOuterAckPublisherProvenanceV3> {
    if option_env!("TRILLIONNIUM_P01_CONFORMANCE_BUILD_VARIANT") != Some("userdebug") {
        bail!("direct_operation_outer_ack_p0_userdebug_compiled_variant_denied");
    }
    let expected_context =
        if provider_id == CODEX.provider_id && adapter == DirectOperationAdapter::SystemApi {
            "u:object_r:trillionnium_codex_system_api_tool_inbox_file:s0"
        } else {
            bail!("direct_operation_outer_ack_p0_userdebug_identity_denied");
        };
    let parent_context = read_selinux_context(parent)?;
    if parent_context != expected_context.as_bytes() {
        bail!("direct_operation_outer_ack_p0_userdebug_parent_selinux_context_drift");
    }
    let product_manifest_sha256 = fixed_environment_digest(
        "TRILLIONNIUM_P01_PRODUCT_MANIFEST_SHA256",
        "direct_operation_outer_ack_p0_product_manifest_digest_denied",
    )?;
    let expected_daemon_sha256 = fixed_environment_digest(
        "TRILLIONNIUM_DAEMON_PAYLOAD_SHA256",
        "direct_operation_outer_ack_p0_daemon_digest_denied",
    )?;
    let daemon_executable_sha256 = sha256_fixed_file(Path::new("/usr/bin/trillionniumd"))?;
    if daemon_executable_sha256 != expected_daemon_sha256 {
        bail!("direct_operation_outer_ack_p0_daemon_measurement_drift");
    }
    let replay_sync_executable_sha256 = fixed_environment_digest(
        "TRILLIONNIUM_P01_REPLAY_SYNC_SHA256",
        "direct_operation_outer_ack_p0_replay_sync_digest_denied",
    )?;
    let parent_identity = identity(parent.as_raw_fd())?;
    let mut filesystem_identity = Sha256::new();
    filesystem_identity.update(b"trillionnium.direct-operation-outer-ack-parent-filesystem.v1\0");
    parent_identity.stable_directory_digest_into(&mut filesystem_identity);
    let provenance = DirectOperationOuterAckPublisherProvenanceV3 {
        schema: ACK_PUBLISHER_PROVENANCE_SCHEMA.to_string(),
        authority_evidence: DirectOperationExecutionAuthorityEvidenceV1::P0UserdebugConformance {
            build_variant: "userdebug".to_string(),
            product_manifest_sha256,
            daemon_executable_sha256,
            replay_sync_executable_sha256,
        },
        fsverity_root_digest_sha256: None,
        parent_filesystem_identity_sha256: format!("{:x}", filesystem_identity.finalize()),
        parent_selinux_context_sha256: sha256_bytes(&parent_context),
    };
    provenance.validate()?;
    Ok(provenance)
}

#[cfg(feature = "p0-launch-package-device-conformance")]
fn fixed_environment_digest(name: &str, denial: &'static str) -> Result<String> {
    let value = std::env::var(name).map_err(|_| anyhow!(denial))?;
    if !valid_nonzero_digest(&value) {
        bail!(denial);
    }
    Ok(value)
}

#[cfg(feature = "p0-launch-package-device-conformance")]
fn sha256_fixed_file(path: &Path) -> Result<String> {
    const MAX_MEASURED_FILE_BYTES: u64 = 128 * 1024 * 1024;
    let mut file = File::open(path).context("direct_operation_outer_ack_p0_daemon_open_failed")?;
    let metadata = file
        .metadata()
        .context("direct_operation_outer_ack_p0_daemon_metadata_failed")?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_MEASURED_FILE_BYTES {
        bail!("direct_operation_outer_ack_p0_daemon_inode_denied");
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut remaining = metadata.len();
    while remaining != 0 {
        let read_limit = usize::try_from(remaining.min(buffer.len() as u64))?;
        let count = file
            .read(&mut buffer[..read_limit])
            .context("direct_operation_outer_ack_p0_daemon_read_failed")?;
        if count == 0 {
            bail!("direct_operation_outer_ack_p0_daemon_truncated");
        }
        hasher.update(&buffer[..count]);
        remaining -= count as u64;
    }
    let mut extra = [0_u8; 1];
    if file.read(&mut extra)? != 0 {
        bail!("direct_operation_outer_ack_p0_daemon_grew_during_measurement");
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(feature = "p0-launch-package-device-conformance")]
fn read_selinux_context(file: &File) -> Result<Vec<u8>> {
    let mut context = vec![0_u8; 4096];
    let count = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            c"security.selinux".as_ptr(),
            context.as_mut_ptr().cast(),
            context.len(),
        )
    };
    if count <= 0 {
        return Err(std::io::Error::last_os_error())
            .context("direct_operation_outer_ack_p0_parent_selinux_xattr_unavailable");
    }
    context.truncate(count as usize);
    while context.last() == Some(&0) {
        context.pop();
    }
    Ok(context)
}

fn source_only_test_publisher_provenance(
    #[cfg(test)] authority_evidence: Option<DirectOperationExecutionAuthorityEvidenceV1>,
) -> Result<DirectOperationOuterAckPublisherProvenanceV3> {
    #[cfg(not(test))]
    bail!("direct_operation_outer_ack_product_provenance_absent");
    #[cfg(test)]
    {
        let digest = |label: &str| sha256_bytes(label.as_bytes());
        let authority_evidence = authority_evidence.unwrap_or_else(|| {
            DirectOperationExecutionAuthorityEvidenceV1::SignedProduct {
                product_descriptor_sha256: digest("test-outer-ack-product-descriptor"),
                signed_product_measurement_sha256: digest("test-outer-ack-signed-product"),
                avb_partition_digest_sha256: digest("test-outer-ack-avb-partition"),
            }
        });
        let fsverity_root_digest_sha256 = match authority_evidence {
            DirectOperationExecutionAuthorityEvidenceV1::SignedProduct { .. } => {
                Some(digest("test-outer-ack-fsverity-root"))
            }
            DirectOperationExecutionAuthorityEvidenceV1::P0UserdebugConformance { .. } => None,
        };
        Ok(DirectOperationOuterAckPublisherProvenanceV3 {
            schema: ACK_PUBLISHER_PROVENANCE_SCHEMA.to_string(),
            authority_evidence,
            fsverity_root_digest_sha256,
            parent_filesystem_identity_sha256: digest("test-outer-ack-parent-filesystem"),
            parent_selinux_context_sha256: digest("test-outer-ack-parent-selinux"),
        })
    }
}

fn publisher_provenance_digest(
    provenance: &DirectOperationOuterAckPublisherProvenanceV3,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"trillionnium.direct-operation-outer-ack-publisher-provenance.v1\0");
    let encoded = serde_json::to_vec(provenance)
        .expect("outer ACK publisher provenance serialization cannot fail");
    hash_field(&mut hasher, &encoded);
    format!("{:x}", hasher.finalize())
}

fn valid_nonzero_digest(value: &str) -> bool {
    value.len() == 64
        && !value.bytes().all(|byte| byte == b'0')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn open_parent(path: &Path) -> Result<File> {
    let path = CString::new(path.as_os_str().as_bytes())
        .context("direct_operation_outer_ack_parent_path_contains_nul")?;
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: OPENAT2_RESOLVE_NO_MAGICLINKS | OPENAT2_RESOLVE_NO_SYMLINKS,
    };
    // SAFETY: path and how are valid for the exact openat2 structure size.
    let raw = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            path.as_ptr(),
            &raw const how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error())
            .context("direct_operation_outer_ack_open_fixed_parent_failed");
    }
    // SAFETY: raw is one successful descriptor, transferred exactly once.
    Ok(unsafe { File::from_raw_fd(raw as RawFd) })
}

fn open_directory_at(parent_fd: RawFd, name: &CStr) -> Result<File> {
    // SAFETY: exact retained parent and a NUL-terminated single component.
    let raw = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error())
            .context("direct_operation_outer_ack_open_archive_failed");
    }
    Ok(unsafe { File::from_raw_fd(raw) })
}

fn mkdir_directory_at(parent_fd: RawFd, name: &CStr) -> std::io::Result<()> {
    // SAFETY: exact retained parent and a fixed relative directory name.
    if unsafe { libc::mkdirat(parent_fd, name.as_ptr(), ACKED_DIRECTORY_MODE) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn open_named_optional(parent_fd: RawFd, name: &CStr) -> Result<Option<File>> {
    // SAFETY: parent_fd is retained and name is NUL-terminated.
    let raw = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            // Regular files ignore O_NONBLOCK; FIFOs/devices never gain an
            // opportunity to stall validation before fstat rejects them.
            //
            // Keep this as part of the open operation rather than setting it
            // after a potentially blocking open.
        )
    };
    if raw >= 0 {
        // SAFETY: raw is one successful descriptor result.
        return Ok(Some(unsafe { File::from_raw_fd(raw) }));
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOENT) {
        Ok(None)
    } else {
        Err(error).context("direct_operation_outer_ack_open_named_failed")
    }
}

fn open_named_readonly(parent_fd: RawFd, name: &CStr) -> Result<File> {
    open_named_optional(parent_fd, name)?.context("direct_operation_outer_ack_named_file_absent")
}

fn open_new_temporary(parent_fd: RawFd, name: &CStr) -> Result<File> {
    // SAFETY: exact parent/name, O_EXCL prevents replacement of any member.
    let raw = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            libc::O_RDWR
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK,
            0o600,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error())
            .context("direct_operation_outer_ack_create_temporary_failed");
    }
    // SAFETY: raw is one successful descriptor result.
    Ok(unsafe { File::from_raw_fd(raw) })
}

fn set_owner_and_mode(file: &File, uid: u32, gid: u32, mode: u32) -> Result<()> {
    // SAFETY: fchown/fchmod operate on one retained descriptor.
    if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("direct_operation_outer_ack_fchown_failed");
    }
    // SAFETY: same retained descriptor and bounded mode.
    if unsafe { libc::fchmod(file.as_raw_fd(), mode) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("direct_operation_outer_ack_fchmod_failed");
    }
    Ok(())
}

fn validate_exact_named(file: &File, expected: &[u8], uid: u32, gid: u32) -> Result<FileIdentity> {
    let file_identity = identity(file.as_raw_fd())?;
    validate_published_identity(file_identity, uid, gid, expected.len())?;
    let bytes = read_exact_bounded(file, MAX_OUTER_ACK_BYTES)?;
    if bytes != expected {
        bail!("direct_operation_outer_ack_existing_bytes_drift");
    }
    Ok(file_identity)
}

fn validate_directory_identity(
    identity: FileIdentity,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<()> {
    if identity.mode & libc::S_IFMT != libc::S_IFDIR
        || identity.mode & 0o7777 != mode
        || identity.uid != uid
        || identity.gid != gid
        || identity.nlink == 0
    {
        bail!("direct_operation_outer_ack_parent_identity_denied");
    }
    Ok(())
}

fn validate_published_identity(
    identity: FileIdentity,
    uid: u32,
    gid: u32,
    expected_len: usize,
) -> Result<()> {
    if identity.mode & libc::S_IFMT != libc::S_IFREG
        || identity.mode & 0o7777 != PUBLISHED_FILE_MODE
        || identity.uid != uid
        || identity.gid != gid
        || identity.nlink != 1
        || identity.size != expected_len as u64
    {
        bail!("direct_operation_outer_ack_file_identity_denied");
    }
    Ok(())
}

fn identity(fd: RawFd) -> Result<FileIdentity> {
    let mut status = MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: status is writable storage for one stat.
    if unsafe { libc::fstat(fd, status.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("direct_operation_outer_ack_fstat_failed");
    }
    // SAFETY: successful fstat initialized status.
    let status = unsafe { status.assume_init() };
    Ok(FileIdentity {
        dev: status.st_dev,
        ino: status.st_ino,
        mode: status.st_mode,
        uid: status.st_uid,
        gid: status.st_gid,
        nlink: normalize_link_count(status.st_nlink),
        size: u64::try_from(status.st_size)
            .map_err(|_| anyhow!("direct_operation_outer_ack_negative_file_size"))?,
    })
}

fn normalize_link_count<T>(value: T) -> u64
where
    u64: From<T>,
{
    u64::from(value)
}

fn read_exact_bounded(file: &File, maximum: usize) -> Result<Vec<u8>> {
    let mut file = file;
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        bail!("direct_operation_outer_ack_readback_oversized");
    }
    Ok(bytes)
}

fn rename_noreplace(parent_fd: RawFd, old: &CStr, new: &CStr) -> std::io::Result<()> {
    rename_noreplace_between(parent_fd, old, parent_fd, new)
}

fn rename_noreplace_between(
    old_parent_fd: RawFd,
    old: &CStr,
    new_parent_fd: RawFd,
    new: &CStr,
) -> std::io::Result<()> {
    // SAFETY: both names are relative to the same retained parent; flag is the
    // Linux UAPI RENAME_NOREPLACE bit.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            old_parent_fd,
            old.as_ptr(),
            new_parent_fd,
            new.as_ptr(),
            RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn unlink_exact_named(parent: &File, name: &CStr, expected: FileIdentity) -> Result<()> {
    let named = open_named_readonly(parent.as_raw_fd(), name)?;
    if identity(named.as_raw_fd())? != expected {
        bail!("direct_operation_outer_ack_unlink_inode_rebound");
    }
    unlink_named(parent.as_raw_fd(), name)
        .context("direct_operation_outer_ack_exact_unlink_failed")?;
    if open_named_optional(parent.as_raw_fd(), name)?.is_some() {
        bail!("direct_operation_outer_ack_exact_unlink_namespace_drift");
    }
    Ok(())
}

fn unlink_named(parent_fd: RawFd, name: &CStr) -> std::io::Result<()> {
    // SAFETY: exact relative name under one retained parent.
    if unsafe { libc::unlinkat(parent_fd, name.as_ptr(), 0) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn cleanup_unpublished_temporary(
    parent: &File,
    name: &CStr,
    temporary: &File,
    durability_uncertain: &mut bool,
) -> Result<()> {
    let open_identity = identity(temporary.as_raw_fd())?;
    let named = open_named_optional(parent.as_raw_fd(), name)?;
    match named {
        Some(named) if identity(named.as_raw_fd())?.same_inode(open_identity) => {}
        Some(_) => {
            *durability_uncertain = true;
            bail!("direct_operation_outer_ack_temporary_name_rebound_hold");
        }
        None => {
            parent
                .sync_all()
                .context("direct_operation_outer_ack_absent_temp_parent_fsync_failed")?;
            return Ok(());
        }
    }
    if let Err(error) = unlink_named(parent.as_raw_fd(), name)
        && error.raw_os_error() != Some(libc::ENOENT)
    {
        *durability_uncertain = true;
        return Err(error).context("direct_operation_outer_ack_temporary_cleanup_unknown");
    }
    if let Err(error) = parent.sync_all() {
        *durability_uncertain = true;
        return Err(error).context("direct_operation_outer_ack_cleanup_parent_fsync_unknown");
    }
    Ok(())
}

fn temporary_name() -> Result<CString> {
    let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    CString::new(format!(
        ".pending-outer-ack-v3.{}.{}.tmp",
        std::process::id(),
        sequence
    ))
    .context("direct_operation_outer_ack_temporary_name_invalid")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_mapping_contains_no_injected_owner_or_path_surface() {
        let source = include_str!("outer_ack_publisher.rs");
        assert!(source.contains("const PRODUCT_INBOX_ROOT"));
        assert!(source.contains("from_provider_agent_pair"));
        assert!(source.contains("rename_noreplace"));
        assert!(source.contains("parent.sync_all()"));
        assert!(!source.contains(concat!("pub(crate) fn for_", "path")));
        assert!(!source.contains(concat!("pub(crate) fn with_", "uid")));
        assert_eq!(
            SOURCE_STATUS,
            "p0_userdebug_fixed_root_outer_ack_v4_publisher_product_authority_held_v2"
        );
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    #[test]
    fn p0_userdebug_publisher_constructor_is_distinct_from_product_authority() {
        let publisher = FixedOuterAckInboxPublisher::from_p0_userdebug_conformance().unwrap();
        assert!(publisher.p0_userdebug_conformance);
        assert!(publisher.product_admission.is_none());
    }
}
