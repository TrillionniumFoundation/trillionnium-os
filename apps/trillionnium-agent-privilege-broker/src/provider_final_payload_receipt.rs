//! Untrusted final-payload receipt parser and retained-FD structural ELF gate.
//!
//! This module is deliberately independent of
//! `linux_provider_post_exec_test_kernel`: the latter accepts compiler-created
//! TempDir fixtures and contains a deliberately limited private parser. Raw
//! daemon-supplied receipt bytes can construct only an internal structural
//! candidate. They do not authenticate a builder, an input artifact, a link
//! map, object-to-final provenance, or a fixed product custody root.
//!
//! The parser remains source-only. There is no authenticated product receipt
//! source, trusted builder set, retained build-input set, listener, admission
//! path, held-chain constructor, or effect-authority conversion. An accepted
//! candidate proves only that one retained AArch64 ELF and one *untrusted*
//! canonical receipt satisfy the bounded structural checks below. It does not
//! prove that the named bootstrap performs hardening or came from the claimed
//! object. Target-kernel, SELinux, cgroup, Android, AVB, and device proofs
//! remain separate prerequisites.
//!
//! The frozen builder under `packaging/provider-post-exec-bootstrap` now emits
//! source-derived single-builder receipts and a non-authorizing 2/2 equality
//! receipt. Those external receipts deliberately have no parser or conversion
//! here: authenticated builder identity and fixed-root receipt intake must be
//! designed before they can become product admission inputs.

use std::collections::BTreeSet;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd as _, RawFd};
use std::os::unix::fs::FileExt as _;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use trillionnium_privilege_broker_protocol::{Digest, FixedBytes32, Provider};

use super::provider_post_exec_bootstrap::{
    ClassicBpfInstruction, exact_aarch64_provider_seccomp_filter, seccomp_filter_sha256,
};

pub(crate) const SOURCE_UNTRUSTED_BUILD_CLAIM_PARSER_IMPLEMENTED: bool = true;
pub(crate) const SOURCE_RETAINED_ELF_STRUCTURAL_INSPECTION_IMPLEMENTED: bool = true;
pub(crate) const SOURCE_FROZEN_EXACT_SOURCE_BUILDER_RECIPE_IMPLEMENTED: bool = true;
pub(crate) const SOURCE_NONAUTHORIZING_TWO_BUILDER_RECEIPT_PRODUCER_IMPLEMENTED: bool = true;
pub(crate) const SOURCE_AUTHENTICATED_BUILD_RECEIPT_IMPLEMENTED: bool = false;
pub(crate) const SOURCE_FIXED_ROOT_FINAL_ELF_CUSTODY_IMPLEMENTED: bool = false;
pub(crate) const SOURCE_OBJECT_TO_FINAL_RANGE_PROVENANCE_IMPLEMENTED: bool = false;
pub(crate) const PRODUCT_PROVIDER_BUILD_RECEIPT_SOURCE_AVAILABLE: bool = false;
pub(crate) const PRODUCT_PROVIDER_FINAL_ELF_GATE_WIRED: bool = false;
pub(crate) const PRODUCT_PROVIDER_PAYLOAD_RECIPE_WIRED: bool = false;
pub(crate) const PRODUCT_LISTENER_BACKEND_AVAILABLE: bool = false;
pub(crate) const PRODUCT_EFFECT_ADMISSION_AVAILABLE: bool = false;
pub(crate) const CONFERS_EFFECT_AUTHORITY: bool = false;

const UNTRUSTED_CLAIM_SCHEMA: &str = "trillionnium-provider-final-payload-candidate-claim-v1";
const UNTRUSTED_CLAIM_DIGEST_DOMAIN: &[u8] =
    b"org.trillionnium.provider-final-payload-candidate-claim.v1\0";
const STRUCTURAL_CANDIDATE_DOMAIN: &[u8] =
    b"org.trillionnium.provider-final-payload-structural-candidate.v1\0";
const NORMALIZED_BUILD_INPUTS_DOMAIN: &[u8] =
    b"org.trillionnium.provider-final-payload-normalized-build-inputs.v1\0";
const MAX_RECEIPT_BYTES: usize = 1_048_576;
const MAX_RECEIPT_ARTIFACTS: usize = 16_384;
const MAX_RECEIPT_ARGUMENTS: usize = 16_384;
const MAX_RECEIPT_ENVIRONMENT: usize = 256;
const MAX_RECEIPT_STRING_BYTES: usize = 16_384;
const MAX_CODEX_ELF_BYTES: u64 = 128 * 1024 * 1024;
const MAX_PROGRAM_HEADERS: usize = 256;
const MAX_SECTION_HEADERS: usize = 4096;
const MAX_SYMBOLS: usize = 1_000_000;

const CODEX_SOURCE_URL: &str = "https://github.com/openai/codex";
const CODEX_SOURCE_TAG: &str = "rust-v0.144.1";
const CODEX_TAG_OBJECT_SHA1: &str = "db75c19352d29ef29c17dbcf73a7244f1b1a8d10";
const CODEX_SOURCE_COMMIT_SHA1: &str = "44918ea10c0f99151c6710411b4322c2f5c96bea";
const CODEX_SOURCE_TREE_SHA1: &str = "6c4d9c247f20ef879c8572eec76798edf9e96425";

const FORBIDDEN_BUILD_TOKEN_FRAGMENTS: &[&str] = &[
    "provider_post_exec_bootstrap_fixture_adapter.h",
    "linux_provider_post_exec_test_kernel.rs",
    "provider_post_exec_bootstrap_fixture.c",
    "provider_post_exec_musl_spawn_fixture.c",
    "FAULT_",
    "TRILLIONNIUM_BOOTSTRAP_",
    "TRILLIONNIUM_PROVIDER_BOOTSTRAP_TEST",
];
const FORBIDDEN_COMPILER_ARGUMENT_PREFIXES: &[&str] =
    &["-include", "-imacros", "-fplugin", "-specs", "--specs"];
// Keep generic process-environment injection defenses in the Codex-only
// receipt even when a variable originates in a runtime Codex does not use.
const FORBIDDEN_ENVIRONMENT_NAMES: &[&str] = &[
    "GLIBC_TUNABLES",
    "NODE_OPTIONS",
    "NODE_PATH",
    "NODE_REPL_EXTERNAL_MODULE",
    "NODE_EXTRA_CA_CERTS",
    "OPENSSL_CONF",
    "SSLKEYLOGFILE",
];
const REQUIRED_BUILDER_ENVIRONMENT_NAMES: &[&str] = &["PATH", "LC_ALL", "TZ", "SOURCE_DATE_EPOCH"];
const ALLOWED_BUILDER_ENVIRONMENT_NAMES: &[&str] = &[
    "PATH",
    "HOME",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "TZ",
    "SOURCE_DATE_EPOCH",
    "CARGO_HOME",
    "RUSTUP_HOME",
    "GIT_CONFIG_NOSYSTEM",
    "GIT_CONFIG_GLOBAL",
];

// libc::nlink_t is u64 on x86-64 and u32 on AArch64. Keep the widening
// conversion explicit on both targets; clippy otherwise flags the x86-64
// instantiation as a useless conversion.
#[allow(clippy::useless_conversion)]
fn normalized_nlink(value: libc::nlink_t) -> u64 {
    u64::from(value)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HashedArtifact {
    pub logical_path: String,
    pub byte_length: u64,
    pub sha256: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnvironmentBinding {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExactSourceReceipt {
    pub repository_url: String,
    pub version: String,
    pub annotated_tag: String,
    pub annotated_tag_object_sha1: String,
    pub dereferenced_commit_sha1: String,
    pub source_tree_sha1: String,
    pub source_archive: Option<HashedArtifact>,
    pub clean_tree: bool,
    pub lockfiles: Vec<HashedArtifact>,
    pub patched_sources: Vec<HashedArtifact>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BootstrapObjectClosureReceipt {
    pub object: HashedArtifact,
    pub relocation_manifest: HashedArtifact,
    pub undefined_symbol_count: u64,
    pub tls_section_count: u64,
    pub plt_section_count: u64,
    pub got_section_count: u64,
    pub ifunc_symbol_count: u64,
    pub init_dependency_count: u64,
    pub preinit_dependency_count: u64,
    pub stack_protector_reference_count: u64,
    pub unexpected_relocation_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BootstrapBuildReceipt {
    pub public_header: HashedArtifact,
    pub freestanding_core_source: HashedArtifact,
    pub controlled_entry_source: Option<HashedArtifact>,
    pub core: BootstrapObjectClosureReceipt,
    pub mechanism_object: HashedArtifact,
    pub exact_filter_sha256: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BuilderIdentityReceipt {
    pub builder_id: String,
    pub builder_image: HashedArtifact,
    pub builder_attestation_sha256: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReproducedOutputReceipt {
    pub final_elf_sha256: Digest,
    pub core_object_sha256: Digest,
    pub mechanism_object_sha256: Digest,
    pub link_map_sha256: Digest,
    pub closure_manifest_sha256: Digest,
    pub normalized_inputs_sha256: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TwoBuilderReproducibilityReceipt {
    pub builders: Vec<BuilderIdentityReceipt>,
    pub outputs: Vec<ReproducedOutputReceipt>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BuildInvocationReceipt {
    pub working_directory: String,
    pub environment: Vec<EnvironmentBinding>,
    pub compiler: HashedArtifact,
    pub assembler: HashedArtifact,
    pub linker: HashedArtifact,
    pub sysroot_manifest: HashedArtifact,
    pub crt_objects: Vec<HashedArtifact>,
    pub compiler_arguments: Vec<String>,
    pub linker_arguments: Vec<String>,
    pub response_files: Vec<ResponseFileReceipt>,
    pub dependency_manifest: HashedArtifact,
    pub dependencies: Vec<HashedArtifact>,
    pub preprocessed_source: HashedArtifact,
    pub macro_dump: HashedArtifact,
    /// Only definitions supplied externally through the compiler invocation.
    /// Legitimate defaults present in the hash-bound macro dump are not
    /// interpreted as overrides.
    pub externally_supplied_definitions: Vec<String>,
    pub ordered_input_objects: Vec<HashedArtifact>,
    pub link_map: HashedArtifact,
    pub closure_manifest: HashedArtifact,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResponseFileReceipt {
    pub file: HashedArtifact,
    /// Exact recursively expanded token stream. Nested `@file` references are
    /// rejected, so a response file cannot hide fixture or override inputs.
    pub expanded_arguments: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CodexControlledEntryExpectation {
    pub controlled_entry_address: u64,
    pub controlled_entry_size: u64,
    pub controlled_entry_sha256: Digest,
    pub bootstrap_core_address: u64,
    pub bootstrap_core_size: u64,
    pub original_start_address: u64,
    pub original_start_size: u64,
    pub original_start_crt_object: HashedArtifact,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ProviderElfExpectation {
    CodexControlledEntry(CodexControlledEntryExpectation),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UntrustedProviderFinalPayloadClaimV1 {
    pub schema: String,
    pub provider: Provider,
    pub target_architecture: String,
    pub source: ExactSourceReceipt,
    pub bootstrap: BootstrapBuildReceipt,
    pub build: BuildInvocationReceipt,
    pub reproducibility: TwoBuilderReproducibilityReceipt,
    pub final_elf: HashedArtifact,
    pub elf_expectation: ProviderElfExpectation,
    pub product_active: bool,
    pub listener_backend_wired: bool,
    pub admission_wired: bool,
    pub confers_effect_authority: bool,
}

#[derive(Serialize)]
struct NormalizedBuildInputs<'a> {
    schema: &'a str,
    provider: Provider,
    target_architecture: &'a str,
    source: &'a ExactSourceReceipt,
    bootstrap: &'a BootstrapBuildReceipt,
    build: &'a BuildInvocationReceipt,
    elf_expectation: &'a ProviderElfExpectation,
    product_active: bool,
    listener_backend_wired: bool,
    admission_wired: bool,
    confers_effect_authority: bool,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum ProviderFinalPayloadGateError {
    #[error("the candidate build receipt is malformed or exceeds its closed schema")]
    ReceiptMalformed,
    #[error("the candidate build receipt contains an unsupported or inconsistent value")]
    ReceiptInvalid,
    #[error("the candidate build receipt contains fixture or override build input")]
    FixtureOrOverrideInput,
    #[error("the candidate build receipt does not contain exact independent 2/2 output equality")]
    ReproducibilityInvalid,
    #[error("the retained final payload could not be opened with closed descriptor semantics")]
    RetainedOpenFailed,
    #[error("the retained final payload ownership, mode, link, or immutability contract failed")]
    RetainedCustodyInvalid,
    #[error("the retained final payload changed while it was measured")]
    RetainedFileDrift,
    #[error("the retained final payload digest or byte length differs from the receipt")]
    FinalElfDigestMismatch,
    #[error("the retained final payload is not a bounded well-formed AArch64 ELF64 image")]
    ElfMalformed,
    #[error("the retained final payload has an unsafe or ambiguous ELF mapping")]
    ElfMappingInvalid,
    #[error("the retained final payload does not match its provider-specific entry contract")]
    ProviderElfContractInvalid,
    #[error("the retained final payload filter bytes differ from the AArch64 source contract")]
    FilterContractInvalid,
}

impl UntrustedProviderFinalPayloadClaimV1 {
    pub(crate) fn parse_and_validate_untrusted_shape(
        bytes: &[u8],
    ) -> Result<(Self, Digest), ProviderFinalPayloadGateError> {
        if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES {
            return Err(ProviderFinalPayloadGateError::ReceiptMalformed);
        }
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        let receipt = Self::deserialize(&mut deserializer)
            .map_err(|_| ProviderFinalPayloadGateError::ReceiptMalformed)?;
        deserializer
            .end()
            .map_err(|_| ProviderFinalPayloadGateError::ReceiptMalformed)?;
        receipt.validate()?;
        let canonical = serde_json::to_vec(&receipt)
            .map_err(|_| ProviderFinalPayloadGateError::ReceiptMalformed)?;
        Ok((
            receipt,
            domain_digest(UNTRUSTED_CLAIM_DIGEST_DOMAIN, &[&canonical]),
        ))
    }

    fn validate(&self) -> Result<(), ProviderFinalPayloadGateError> {
        if self.schema != UNTRUSTED_CLAIM_SCHEMA
            || self.target_architecture != "aarch64-unknown-linux"
            || self.product_active
            || self.listener_backend_wired
            || self.admission_wired
            || self.confers_effect_authority
        {
            return Err(ProviderFinalPayloadGateError::ReceiptInvalid);
        }
        self.source.validate()?;
        self.bootstrap.validate()?;
        self.build.validate()?;
        self.reproducibility.validate(self)?;
        validate_artifact(&self.final_elf)?;
        let ProviderElfExpectation::CodexControlledEntry(expectation) = &self.elf_expectation;
        expectation.validate()?;
        self.validate_cross_field_closure()?;
        Ok(())
    }

    fn normalized_inputs_sha256(&self) -> Result<Digest, ProviderFinalPayloadGateError> {
        let canonical = serde_json::to_vec(&NormalizedBuildInputs {
            schema: &self.schema,
            provider: self.provider,
            target_architecture: &self.target_architecture,
            source: &self.source,
            bootstrap: &self.bootstrap,
            build: &self.build,
            elf_expectation: &self.elf_expectation,
            product_active: self.product_active,
            listener_backend_wired: self.listener_backend_wired,
            admission_wired: self.admission_wired,
            confers_effect_authority: self.confers_effect_authority,
        })
        .map_err(|_| ProviderFinalPayloadGateError::ReceiptMalformed)?;
        Ok(domain_digest(NORMALIZED_BUILD_INPUTS_DOMAIN, &[&canonical]))
    }

    fn validate_cross_field_closure(&self) -> Result<(), ProviderFinalPayloadGateError> {
        if self.bootstrap.core.object == self.bootstrap.mechanism_object
            || count_artifact(
                &self.build.ordered_input_objects,
                &self.bootstrap.core.object,
            ) != 1
            || count_artifact(
                &self.build.ordered_input_objects,
                &self.bootstrap.mechanism_object,
            ) != 1
        {
            return Err(ProviderFinalPayloadGateError::ReceiptInvalid);
        }
        let ProviderElfExpectation::CodexControlledEntry(expectation) = &self.elf_expectation;
        if count_artifact(
            &self.build.crt_objects,
            &expectation.original_start_crt_object,
        ) != 1
            || count_artifact(
                &self.build.ordered_input_objects,
                &expectation.original_start_crt_object,
            ) != 1
            || Path::new(&self.final_elf.logical_path)
                .file_name()
                .and_then(|name| name.to_str())
                != Some("codex")
        {
            return Err(ProviderFinalPayloadGateError::ReceiptInvalid);
        }
        Ok(())
    }
}

impl ExactSourceReceipt {
    fn validate(&self) -> Result<(), ProviderFinalPayloadGateError> {
        validate_string(&self.repository_url)?;
        validate_string(&self.version)?;
        validate_string(&self.annotated_tag)?;
        validate_git_sha1(&self.annotated_tag_object_sha1)?;
        validate_git_sha1(&self.dereferenced_commit_sha1)?;
        validate_git_sha1(&self.source_tree_sha1)?;
        if !self.clean_tree || self.lockfiles.is_empty() {
            return Err(ProviderFinalPayloadGateError::ReceiptInvalid);
        }
        validate_artifacts(&self.lockfiles)?;
        validate_artifacts(&self.patched_sources)?;
        if let Some(archive) = &self.source_archive {
            validate_artifact(archive)?;
        }
        let pins_match = self.repository_url == CODEX_SOURCE_URL
            && self.version == "0.144.1"
            && self.annotated_tag == CODEX_SOURCE_TAG
            && self.annotated_tag_object_sha1 == CODEX_TAG_OBJECT_SHA1
            && self.dereferenced_commit_sha1 == CODEX_SOURCE_COMMIT_SHA1
            && self.source_tree_sha1 == CODEX_SOURCE_TREE_SHA1;
        if !pins_match {
            return Err(ProviderFinalPayloadGateError::ReceiptInvalid);
        }
        Ok(())
    }
}

impl BootstrapBuildReceipt {
    fn validate(&self) -> Result<(), ProviderFinalPayloadGateError> {
        validate_artifact(&self.public_header)?;
        validate_artifact(&self.freestanding_core_source)?;
        validate_artifact(&self.core.object)?;
        validate_artifact(&self.core.relocation_manifest)?;
        validate_artifact(&self.mechanism_object)?;
        let expected_filter = seccomp_filter_sha256(&exact_aarch64_provider_seccomp_filter());
        if self.exact_filter_sha256 != expected_filter
            || self.core.undefined_symbol_count != 0
            || self.core.tls_section_count != 0
            || self.core.plt_section_count != 0
            || self.core.got_section_count != 0
            || self.core.ifunc_symbol_count != 0
            || self.core.init_dependency_count != 0
            || self.core.preinit_dependency_count != 0
            || self.core.stack_protector_reference_count != 0
            || self.core.unexpected_relocation_count != 0
        {
            return Err(ProviderFinalPayloadGateError::ReceiptInvalid);
        }
        validate_artifact(
            self.controlled_entry_source
                .as_ref()
                .ok_or(ProviderFinalPayloadGateError::ReceiptInvalid)?,
        )?;
        Ok(())
    }
}

impl BuildInvocationReceipt {
    fn validate(&self) -> Result<(), ProviderFinalPayloadGateError> {
        validate_string(&self.working_directory)?;
        if !self.working_directory.starts_with('/') {
            return Err(ProviderFinalPayloadGateError::ReceiptInvalid);
        }
        for artifact in [
            &self.compiler,
            &self.assembler,
            &self.linker,
            &self.sysroot_manifest,
            &self.dependency_manifest,
            &self.preprocessed_source,
            &self.macro_dump,
            &self.link_map,
            &self.closure_manifest,
        ] {
            validate_artifact(artifact)?;
        }
        validate_artifacts(&self.crt_objects)?;
        validate_artifacts(&self.dependencies)?;
        validate_artifacts(&self.ordered_input_objects)?;
        if self.crt_objects.is_empty()
            || self.dependencies.is_empty()
            || self.ordered_input_objects.is_empty()
            || self.compiler_arguments.is_empty()
            || self.linker_arguments.is_empty()
            || self.compiler_arguments.len() > MAX_RECEIPT_ARGUMENTS
            || self.linker_arguments.len() > MAX_RECEIPT_ARGUMENTS
            || self.response_files.len() > MAX_RECEIPT_ARTIFACTS
            || self.externally_supplied_definitions.len() > MAX_RECEIPT_ARGUMENTS
            || self.environment.len() > MAX_RECEIPT_ENVIRONMENT
        {
            return Err(ProviderFinalPayloadGateError::ReceiptInvalid);
        }

        let mut response_names = BTreeSet::new();
        for response in &self.response_files {
            validate_artifact(&response.file)?;
            if response.expanded_arguments.is_empty()
                || response.expanded_arguments.len() > MAX_RECEIPT_ARGUMENTS
                || !response_names.insert(response.file.logical_path.as_str())
            {
                return Err(ProviderFinalPayloadGateError::ReceiptInvalid);
            }
            for argument in &response.expanded_arguments {
                validate_expanded_build_argument(argument)?;
                if argument.starts_with('@') {
                    return Err(ProviderFinalPayloadGateError::FixtureOrOverrideInput);
                }
            }
        }
        for argument in self
            .compiler_arguments
            .iter()
            .chain(self.linker_arguments.iter())
        {
            validate_expanded_build_argument(argument)?;
            if let Some(response) = argument.strip_prefix('@')
                && !response_names.contains(response)
            {
                return Err(ProviderFinalPayloadGateError::ReceiptInvalid);
            }
        }
        let mut macro_names = BTreeSet::new();
        for name in &self.externally_supplied_definitions {
            validate_identifier(name)?;
            reject_forbidden_build_token(name)?;
            if !macro_names.insert(name.as_str()) {
                return Err(ProviderFinalPayloadGateError::ReceiptInvalid);
            }
        }
        validate_builder_environment(&self.environment)?;
        Ok(())
    }
}

impl TwoBuilderReproducibilityReceipt {
    fn validate(
        &self,
        receipt: &UntrustedProviderFinalPayloadClaimV1,
    ) -> Result<(), ProviderFinalPayloadGateError> {
        if self.builders.len() != 2 || self.outputs.len() != 2 {
            return Err(ProviderFinalPayloadGateError::ReproducibilityInvalid);
        }
        for builder in &self.builders {
            validate_string(&builder.builder_id)?;
            validate_artifact(&builder.builder_image)?;
        }
        if self.builders[0].builder_id == self.builders[1].builder_id
            || self.builders[0].builder_attestation_sha256
                == self.builders[1].builder_attestation_sha256
            || self.outputs[0] != self.outputs[1]
        {
            return Err(ProviderFinalPayloadGateError::ReproducibilityInvalid);
        }
        let output = &self.outputs[0];
        let normalized = receipt.normalized_inputs_sha256()?;
        if output.final_elf_sha256 != receipt.final_elf.sha256
            || output.core_object_sha256 != receipt.bootstrap.core.object.sha256
            || output.mechanism_object_sha256 != receipt.bootstrap.mechanism_object.sha256
            || output.link_map_sha256 != receipt.build.link_map.sha256
            || output.closure_manifest_sha256 != receipt.build.closure_manifest.sha256
            || output.normalized_inputs_sha256 != normalized
        {
            return Err(ProviderFinalPayloadGateError::ReproducibilityInvalid);
        }
        Ok(())
    }
}

impl CodexControlledEntryExpectation {
    fn validate(&self) -> Result<(), ProviderFinalPayloadGateError> {
        validate_artifact(&self.original_start_crt_object)?;
        if self.controlled_entry_size != 32
            || !self.original_start_size.is_multiple_of(4)
            || !aarch64_code_ranges_are_aligned_and_disjoint(&[
                (self.controlled_entry_address, self.controlled_entry_size),
                (self.bootstrap_core_address, self.bootstrap_core_size),
                (self.original_start_address, self.original_start_size.max(4)),
            ])
        {
            return Err(ProviderFinalPayloadGateError::ReceiptInvalid);
        }
        Ok(())
    }
}

fn aarch64_code_ranges_are_aligned_and_disjoint(ranges: &[(u64, u64)]) -> bool {
    let checked = ranges
        .iter()
        .map(|&(start, size)| {
            (start != 0 && size != 0 && start % 4 == 0 && size % 4 == 0)
                .then(|| start.checked_add(size))
                .flatten()
                .map(|end| (start, end))
        })
        .collect::<Option<Vec<_>>>();
    checked.is_some_and(|checked| {
        checked.iter().enumerate().all(|(index, &(start, end))| {
            checked[..index].iter().all(|&(other_start, other_end)| {
                !ranges_overlap(start, end, other_start, other_end)
            })
        })
    })
}

fn validate_builder_environment(
    environment: &[EnvironmentBinding],
) -> Result<(), ProviderFinalPayloadGateError> {
    validate_environment_names_and_values(environment)?;
    let names = environment
        .iter()
        .map(|entry| entry.name.as_str())
        .collect::<BTreeSet<_>>();
    if REQUIRED_BUILDER_ENVIRONMENT_NAMES
        .iter()
        .any(|name| !names.contains(name))
        || names
            .iter()
            .any(|name| !ALLOWED_BUILDER_ENVIRONMENT_NAMES.contains(name))
    {
        return Err(ProviderFinalPayloadGateError::ReceiptInvalid);
    }
    Ok(())
}

fn validate_environment_names_and_values(
    environment: &[EnvironmentBinding],
) -> Result<(), ProviderFinalPayloadGateError> {
    let mut names = BTreeSet::new();
    for entry in environment {
        validate_identifier(&entry.name)?;
        validate_string(&entry.value)?;
        if !names.insert(entry.name.as_str())
            || entry.name.starts_with("LD_")
            || FORBIDDEN_ENVIRONMENT_NAMES.contains(&entry.name.as_str())
        {
            return Err(ProviderFinalPayloadGateError::ReceiptInvalid);
        }
    }
    Ok(())
}

fn count_artifact(artifacts: &[HashedArtifact], expected: &HashedArtifact) -> usize {
    artifacts
        .iter()
        .filter(|artifact| *artifact == expected)
        .count()
}

fn validate_artifacts(artifacts: &[HashedArtifact]) -> Result<(), ProviderFinalPayloadGateError> {
    if artifacts.len() > MAX_RECEIPT_ARTIFACTS {
        return Err(ProviderFinalPayloadGateError::ReceiptInvalid);
    }
    let mut paths = BTreeSet::new();
    for artifact in artifacts {
        validate_artifact(artifact)?;
        if !paths.insert(artifact.logical_path.as_str()) {
            return Err(ProviderFinalPayloadGateError::ReceiptInvalid);
        }
    }
    Ok(())
}

fn validate_artifact(artifact: &HashedArtifact) -> Result<(), ProviderFinalPayloadGateError> {
    validate_string(&artifact.logical_path)?;
    reject_forbidden_build_token(&artifact.logical_path)?;
    if artifact.byte_length == 0
        || artifact.logical_path.contains("/../")
        || artifact.logical_path.ends_with("/..")
    {
        return Err(ProviderFinalPayloadGateError::ReceiptInvalid);
    }
    Ok(())
}

fn validate_unique_strings(values: &[String]) -> Result<(), ProviderFinalPayloadGateError> {
    if values.len() > MAX_RECEIPT_ARTIFACTS {
        return Err(ProviderFinalPayloadGateError::ReceiptInvalid);
    }
    let mut unique = BTreeSet::new();
    for value in values {
        validate_string(value)?;
        if !unique.insert(value.as_str()) {
            return Err(ProviderFinalPayloadGateError::ReceiptInvalid);
        }
    }
    Ok(())
}

fn validate_git_sha1(value: &str) -> Result<(), ProviderFinalPayloadGateError> {
    if value.len() != 40
        || value.bytes().all(|byte| byte == b'0')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProviderFinalPayloadGateError::ReceiptInvalid);
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), ProviderFinalPayloadGateError> {
    validate_string(value)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(ProviderFinalPayloadGateError::ReceiptInvalid);
    }
    Ok(())
}

fn validate_string(value: &str) -> Result<(), ProviderFinalPayloadGateError> {
    if value.is_empty() || value.len() > MAX_RECEIPT_STRING_BYTES || value.contains('\0') {
        return Err(ProviderFinalPayloadGateError::ReceiptInvalid);
    }
    Ok(())
}

fn reject_forbidden_build_token(value: &str) -> Result<(), ProviderFinalPayloadGateError> {
    if FORBIDDEN_BUILD_TOKEN_FRAGMENTS
        .iter()
        .any(|fragment| value.contains(fragment))
    {
        return Err(ProviderFinalPayloadGateError::FixtureOrOverrideInput);
    }
    Ok(())
}

fn validate_expanded_build_argument(argument: &str) -> Result<(), ProviderFinalPayloadGateError> {
    validate_string(argument)?;
    reject_forbidden_build_token(argument)?;
    if FORBIDDEN_COMPILER_ARGUMENT_PREFIXES
        .iter()
        .any(|prefix| argument.starts_with(prefix))
    {
        return Err(ProviderFinalPayloadGateError::FixtureOrOverrideInput);
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct RetainedFilePolicy {
    expected_uid: u32,
    expected_gid: u32,
    require_root_immutable_or_read_only_mount: bool,
}

const PRODUCT_RETAINED_FILE_POLICY: RetainedFilePolicy = RetainedFilePolicy {
    expected_uid: 0,
    expected_gid: 0,
    require_root_immutable_or_read_only_mount: true,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RetainedFileStat {
    device: u64,
    inode: u64,
    mode: u32,
    links: u64,
    uid: u32,
    gid: u32,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

/// Affine retention of one structurally checked final-ELF candidate.
///
/// The receipt is explicitly untrusted. No accessor yields the retained
/// descriptor, and no conversion exists into trusted build custody, launch,
/// listener, admission, or effect authority.
#[derive(Debug)]
#[must_use = "a structurally checked final-payload candidate is affine and untrusted"]
struct RetainedProviderFinalElfStructuralCandidate {
    _retained_final_elf: File,
    provider: Provider,
    untrusted_claim_sha256: Digest,
    final_elf_sha256: Digest,
    structural_candidate_sha256: Digest,
}

fn inspect_retained_provider_final_elf_candidate(
    retained: File,
    claim_bytes: &[u8],
    policy: RetainedFilePolicy,
) -> Result<RetainedProviderFinalElfStructuralCandidate, ProviderFinalPayloadGateError> {
    let (claim, claim_sha256) =
        UntrustedProviderFinalPayloadClaimV1::parse_and_validate_untrusted_shape(claim_bytes)?;
    let descriptor_flags = unsafe { libc::fcntl(retained.as_raw_fd(), libc::F_GETFD) };
    let status_flags = unsafe { libc::fcntl(retained.as_raw_fd(), libc::F_GETFL) };
    if descriptor_flags < 0
        || descriptor_flags & libc::FD_CLOEXEC == 0
        || status_flags < 0
        || status_flags & libc::O_ACCMODE != libc::O_RDONLY
    {
        return Err(ProviderFinalPayloadGateError::RetainedCustodyInvalid);
    }
    let before = retained_file_stat(retained.as_raw_fd())?;
    validate_retained_file_stat(retained.as_raw_fd(), before, policy)?;
    let maximum = match claim.provider {
        Provider::Codex => MAX_CODEX_ELF_BYTES,
    };
    if before.size < ELF_HEADER_SIZE as u64 || before.size > maximum {
        return Err(ProviderFinalPayloadGateError::RetainedCustodyInvalid);
    }
    let byte_length = usize::try_from(before.size)
        .map_err(|_| ProviderFinalPayloadGateError::RetainedCustodyInvalid)?;
    let mut bytes = vec![0_u8; byte_length];
    retained
        .read_exact_at(&mut bytes, 0)
        .map_err(|_| ProviderFinalPayloadGateError::RetainedFileDrift)?;
    let after = retained_file_stat(retained.as_raw_fd())?;
    if before != after {
        return Err(ProviderFinalPayloadGateError::RetainedFileDrift);
    }
    let final_elf_sha256 = sha256_digest(&bytes);
    if claim.final_elf.byte_length != before.size || claim.final_elf.sha256 != final_elf_sha256 {
        return Err(ProviderFinalPayloadGateError::FinalElfDigestMismatch);
    }
    let facts = ParsedElf::parse_and_validate(&bytes)?;
    facts.verify_provider_contract(&bytes, &claim)?;
    let provider = [provider_discriminator(claim.provider)];
    let structural_candidate_sha256 = domain_digest(
        STRUCTURAL_CANDIDATE_DOMAIN,
        &[
            &provider,
            claim_sha256.value().as_bytes(),
            final_elf_sha256.value().as_bytes(),
            claim.bootstrap.exact_filter_sha256.value().as_bytes(),
        ],
    );
    Ok(RetainedProviderFinalElfStructuralCandidate {
        _retained_final_elf: retained,
        provider: claim.provider,
        untrusted_claim_sha256: claim_sha256,
        final_elf_sha256,
        structural_candidate_sha256,
    })
}

fn retained_file_stat(fd: RawFd) -> Result<RetainedFileStat, ProviderFinalPayloadGateError> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return Err(ProviderFinalPayloadGateError::RetainedCustodyInvalid);
    }
    let stat = unsafe { stat.assume_init() };
    Ok(RetainedFileStat {
        device: stat.st_dev,
        inode: stat.st_ino,
        mode: stat.st_mode,
        links: normalized_nlink(stat.st_nlink),
        uid: stat.st_uid,
        gid: stat.st_gid,
        size: u64::try_from(stat.st_size)
            .map_err(|_| ProviderFinalPayloadGateError::RetainedCustodyInvalid)?,
        modified_seconds: stat.st_mtime,
        modified_nanoseconds: stat.st_mtime_nsec,
        changed_seconds: stat.st_ctime,
        changed_nanoseconds: stat.st_ctime_nsec,
    })
}

fn validate_retained_file_stat(
    fd: RawFd,
    stat: RetainedFileStat,
    policy: RetainedFilePolicy,
) -> Result<(), ProviderFinalPayloadGateError> {
    let file_type = stat.mode & libc::S_IFMT;
    let permissions = stat.mode & 0o7777;
    if file_type != libc::S_IFREG
        || stat.links != 1
        || stat.uid != policy.expected_uid
        || stat.gid != policy.expected_gid
        || permissions & 0o7022 != 0
        || permissions & 0o0111 == 0
        || permissions & 0o0400 == 0
    {
        return Err(ProviderFinalPayloadGateError::RetainedCustodyInvalid);
    }
    if policy.require_root_immutable_or_read_only_mount
        && !inode_is_immutable(fd)?
        && !mount_is_read_only(fd)?
    {
        return Err(ProviderFinalPayloadGateError::RetainedCustodyInvalid);
    }
    Ok(())
}

fn inode_is_immutable(fd: RawFd) -> Result<bool, ProviderFinalPayloadGateError> {
    #[cfg(all(target_arch = "aarch64", target_env = "musl"))]
    const FS_IOC_GETFLAGS: libc::c_int = 0x8008_6601_u32 as libc::c_int;
    #[cfg(not(all(target_arch = "aarch64", target_env = "musl")))]
    const FS_IOC_GETFLAGS: libc::c_ulong = 0x8008_6601;
    const FS_IMMUTABLE_FL: libc::c_long = 0x0000_0010;
    let mut flags: libc::c_long = 0;
    if unsafe { libc::ioctl(fd, FS_IOC_GETFLAGS, &mut flags) } != 0 {
        let error = io::Error::last_os_error();
        if matches!(
            error.raw_os_error(),
            Some(libc::ENOTTY) | Some(libc::EOPNOTSUPP) | Some(libc::EINVAL)
        ) {
            return Ok(false);
        }
        return Err(ProviderFinalPayloadGateError::RetainedCustodyInvalid);
    }
    Ok(flags & FS_IMMUTABLE_FL != 0)
}

fn mount_is_read_only(fd: RawFd) -> Result<bool, ProviderFinalPayloadGateError> {
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
    if unsafe { libc::fstatvfs(fd, stat.as_mut_ptr()) } != 0 {
        return Err(ProviderFinalPayloadGateError::RetainedCustodyInvalid);
    }
    Ok(unsafe { stat.assume_init() }.f_flag & libc::ST_RDONLY != 0)
}

const ELF_HEADER_SIZE: usize = 64;
const PROGRAM_HEADER_SIZE: usize = 56;
const SECTION_HEADER_SIZE: usize = 64;
const SYMBOL_ENTRY_SIZE: usize = 24;

const ET_EXEC: u16 = 2;
const EM_AARCH64: u16 = 183;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_TLS: u32 = 7;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PT_GNU_RELRO: u32 = 0x6474_e552;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

const SHT_NULL: u32 = 0;
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHT_DYNAMIC: u32 = 6;
const SHT_NOBITS: u32 = 8;
const SHT_REL: u32 = 9;
const SHT_DYNSYM: u32 = 11;
const SHT_INIT_ARRAY: u32 = 14;
const SHT_PREINIT_ARRAY: u32 = 16;
const SHT_RELR: u32 = 19;
const SHF_WRITE: u64 = 1;
const SHF_ALLOC: u64 = 2;
const SHF_EXECINSTR: u64 = 4;
const SHF_TLS: u64 = 0x400;

const STB_GLOBAL: u8 = 1;
const STT_NOTYPE: u8 = 0;
const STT_FUNC: u8 = 2;
const STT_GNU_IFUNC: u8 = 10;
const STV_DEFAULT: u8 = 0;
const STV_HIDDEN: u8 = 2;
const SHN_UNDEF: u16 = 0;
const SHN_ABS: u16 = 0xfff1;
const SHN_COMMON: u16 = 0xfff2;
const SHN_XINDEX: u16 = 0xffff;
const PN_XNUM: u16 = 0xffff;

#[derive(Clone, Copy, Debug)]
struct ElfHeader {
    elf_type: u16,
    entry: u64,
}

#[derive(Clone, Copy, Debug)]
struct ProgramHeader {
    program_type: u32,
    flags: u32,
    offset: u64,
    virtual_address: u64,
    file_size: u64,
    memory_size: u64,
    alignment: u64,
}

impl ProgramHeader {
    fn file_end(self) -> Option<u64> {
        self.offset.checked_add(self.file_size)
    }

    fn memory_end(self) -> Option<u64> {
        self.virtual_address.checked_add(self.memory_size)
    }

    fn contains_memory(self, address: u64, size: u64) -> bool {
        address >= self.virtual_address
            && address
                .checked_add(size)
                .zip(self.memory_end())
                .is_some_and(|(end, segment_end)| end <= segment_end)
    }

    fn contains_file_mapping(self, address: u64, offset: u64, size: u64) -> bool {
        if !self.contains_memory(address, size) {
            return false;
        }
        offset >= self.offset
            && offset
                .checked_add(size)
                .zip(self.file_end())
                .is_some_and(|(end, segment_end)| end <= segment_end)
            && address.checked_sub(self.virtual_address) == offset.checked_sub(self.offset)
    }
}

#[derive(Clone, Debug)]
struct SectionHeader {
    index: usize,
    name: String,
    section_type: u32,
    flags: u64,
    address: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    alignment: u64,
    entry_size: u64,
}

impl SectionHeader {
    fn memory_end(&self) -> Option<u64> {
        self.address.checked_add(self.size)
    }

    fn file_end(&self) -> Option<u64> {
        self.offset.checked_add(self.size)
    }
}

#[derive(Clone, Debug)]
struct ElfSymbol {
    table_type: u32,
    name: String,
    binding: u8,
    symbol_type: u8,
    visibility: u8,
    section_index: u16,
    value: u64,
    size: u64,
}

#[derive(Clone, Debug)]
struct ParsedElf {
    header: ElfHeader,
    programs: Vec<ProgramHeader>,
    sections: Vec<SectionHeader>,
    symbols: Vec<ElfSymbol>,
}

impl ParsedElf {
    fn parse_and_validate(bytes: &[u8]) -> Result<Self, ProviderFinalPayloadGateError> {
        if bytes.len() < ELF_HEADER_SIZE
            || bytes.get(..4) != Some(b"\x7fELF")
            || bytes.get(4) != Some(&2)
            || bytes.get(5) != Some(&1)
            || bytes.get(6) != Some(&1)
            || !matches!(bytes.get(7), Some(&0) | Some(&3))
            || bytes.get(8) != Some(&0)
        {
            return Err(ProviderFinalPayloadGateError::ElfMalformed);
        }
        let elf_type = read_u16(bytes, 16)?;
        let machine = read_u16(bytes, 18)?;
        let version = read_u32(bytes, 20)?;
        let entry = read_u64(bytes, 24)?;
        let program_offset = read_u64(bytes, 32)?;
        let section_offset = read_u64(bytes, 40)?;
        let flags = read_u32(bytes, 48)?;
        let header_size = read_u16(bytes, 52)?;
        let program_entry_size = read_u16(bytes, 54)?;
        let program_count = read_u16(bytes, 56)?;
        let section_entry_size = read_u16(bytes, 58)?;
        let section_count = read_u16(bytes, 60)?;
        let section_name_index = read_u16(bytes, 62)?;
        if elf_type != ET_EXEC
            || machine != EM_AARCH64
            || version != 1
            || flags != 0
            || usize::from(header_size) != ELF_HEADER_SIZE
            || usize::from(program_entry_size) != PROGRAM_HEADER_SIZE
            || program_count == 0
            || program_count == PN_XNUM
            || usize::from(program_count) > MAX_PROGRAM_HEADERS
            || usize::from(section_entry_size) != SECTION_HEADER_SIZE
            || section_count == 0
            || usize::from(section_count) > MAX_SECTION_HEADERS
            || section_name_index == SHN_XINDEX
            || section_name_index >= section_count
        {
            return Err(ProviderFinalPayloadGateError::ElfMalformed);
        }
        checked_table_range(
            program_offset,
            usize::from(program_count),
            PROGRAM_HEADER_SIZE,
            bytes.len(),
        )?;
        checked_table_range(
            section_offset,
            usize::from(section_count),
            SECTION_HEADER_SIZE,
            bytes.len(),
        )?;

        let programs = parse_program_headers(bytes, program_offset, program_count)?;
        validate_program_headers(bytes, &programs)?;
        let sections =
            parse_section_headers(bytes, section_offset, section_count, section_name_index)?;
        validate_section_headers(bytes, &programs, &sections)?;
        let symbols = parse_and_validate_symbols(bytes, &sections)?;
        Ok(Self {
            header: ElfHeader { elf_type, entry },
            programs,
            sections,
            symbols,
        })
    }

    fn verify_provider_contract(
        &self,
        bytes: &[u8],
        claim: &UntrustedProviderFinalPayloadClaimV1,
    ) -> Result<(), ProviderFinalPayloadGateError> {
        self.verify_exact_filter(bytes, claim.bootstrap.exact_filter_sha256)?;
        let ProviderElfExpectation::CodexControlledEntry(expectation) = &claim.elf_expectation;
        self.verify_codex(bytes, expectation)
    }

    fn verify_exact_filter(
        &self,
        bytes: &[u8],
        expected_digest: Digest,
    ) -> Result<(), ProviderFinalPayloadGateError> {
        let sections = self
            .sections
            .iter()
            .filter(|section| section.name == ".trillionnium.provider_filter")
            .collect::<Vec<_>>();
        let [section] = sections.as_slice() else {
            return Err(ProviderFinalPayloadGateError::FilterContractInvalid);
        };
        let expected = exact_filter_bytes(&exact_aarch64_provider_seccomp_filter());
        if section.section_type != SHT_PROGBITS
            || section.flags & SHF_ALLOC == 0
            || section.flags & (SHF_WRITE | SHF_EXECINSTR) != 0
            || section.size != expected.len() as u64
            || section_bytes(bytes, section)? != expected
            || seccomp_filter_sha256(&exact_aarch64_provider_seccomp_filter()) != expected_digest
        {
            return Err(ProviderFinalPayloadGateError::FilterContractInvalid);
        }
        let mappings = self
            .programs
            .iter()
            .filter(|program| {
                program.program_type == PT_LOAD
                    && program.contains_file_mapping(section.address, section.offset, section.size)
                    && program.flags & (PF_W | PF_X) == 0
                    && program.flags & PF_R != 0
            })
            .count();
        if mappings != 1 {
            return Err(ProviderFinalPayloadGateError::FilterContractInvalid);
        }
        Ok(())
    }

    fn verify_codex(
        &self,
        bytes: &[u8],
        expectation: &CodexControlledEntryExpectation,
    ) -> Result<(), ProviderFinalPayloadGateError> {
        if self.header.elf_type != ET_EXEC
            || self.header.entry != expectation.controlled_entry_address
            || self
                .programs
                .iter()
                .any(|program| matches!(program.program_type, PT_INTERP | PT_DYNAMIC))
            || self
                .sections
                .iter()
                .any(|section| section.section_type == SHT_DYNAMIC)
            || self
                .sections
                .iter()
                .any(|section| section.section_type == SHT_PREINIT_ARRAY)
            || self.sections.iter().any(|section| {
                section.flags & SHF_ALLOC != 0
                    && matches!(section.section_type, SHT_RELA | SHT_REL | SHT_RELR)
            })
        {
            return Err(ProviderFinalPayloadGateError::ProviderElfContractInvalid);
        }

        let controlled_entry =
            self.exact_symbol("trillionnium_provider_post_final_exec_entry", SHT_SYMTAB)?;
        let bootstrap = self.exact_symbol(
            "trillionnium_provider_post_final_exec_bootstrap",
            SHT_SYMTAB,
        )?;
        let original_start = self.exact_symbol("_start", SHT_SYMTAB)?;
        if !symbol_matches(
            controlled_entry,
            STB_GLOBAL,
            STT_FUNC,
            STV_HIDDEN,
            expectation.controlled_entry_address,
            expectation.controlled_entry_size,
        ) || !symbol_matches(
            bootstrap,
            STB_GLOBAL,
            STT_FUNC,
            STV_HIDDEN,
            expectation.bootstrap_core_address,
            expectation.bootstrap_core_size,
        ) || original_start.binding != STB_GLOBAL
            || !matches!(original_start.symbol_type, STT_NOTYPE | STT_FUNC)
            || original_start.visibility != STV_DEFAULT
            || original_start.value != expectation.original_start_address
            || original_start.size != expectation.original_start_size
            || controlled_entry.value == bootstrap.value
            || controlled_entry.value == original_start.value
            || bootstrap.value == original_start.value
        {
            return Err(ProviderFinalPayloadGateError::ProviderElfContractInvalid);
        }
        for symbol in [controlled_entry, bootstrap, original_start] {
            if !self.symbol_has_rx_section_provenance(symbol)
                || self
                    .unique_load_for_range(symbol.value, symbol.size.max(4), PF_R | PF_X, PF_W)
                    .is_none()
            {
                return Err(ProviderFinalPayloadGateError::ProviderElfContractInvalid);
            }
        }
        let entry_bytes =
            self.bytes_at_virtual_address(bytes, controlled_entry.value, controlled_entry.size)?;
        if sha256_digest(entry_bytes) != expectation.controlled_entry_sha256
            || !validate_aarch64_controlled_entry(
                entry_bytes,
                controlled_entry.value,
                bootstrap.value,
                original_start.value,
            )
        {
            return Err(ProviderFinalPayloadGateError::ProviderElfContractInvalid);
        }
        Ok(())
    }

    fn exact_symbol(
        &self,
        name: &str,
        table_type: u32,
    ) -> Result<&ElfSymbol, ProviderFinalPayloadGateError> {
        let symbols = self
            .symbols
            .iter()
            .filter(|symbol| symbol.table_type == table_type && symbol.name == name)
            .collect::<Vec<_>>();
        let [symbol] = symbols.as_slice() else {
            return Err(ProviderFinalPayloadGateError::ProviderElfContractInvalid);
        };
        Ok(symbol)
    }

    fn symbol_has_rx_section_provenance(&self, symbol: &ElfSymbol) -> bool {
        if symbol.size == 0
            || matches!(
                symbol.section_index,
                SHN_UNDEF | SHN_ABS | SHN_COMMON | SHN_XINDEX
            )
        {
            return false;
        }
        self.sections
            .get(usize::from(symbol.section_index))
            .is_some_and(|section| {
                section.section_type == SHT_PROGBITS
                    && section.flags & (SHF_ALLOC | SHF_EXECINSTR) == (SHF_ALLOC | SHF_EXECINSTR)
                    && section.flags & SHF_WRITE == 0
                    && symbol.value >= section.address
                    && symbol
                        .value
                        .checked_add(symbol.size)
                        .zip(section.memory_end())
                        .is_some_and(|(symbol_end, section_end)| symbol_end <= section_end)
            })
    }

    fn unique_load_for_range(
        &self,
        address: u64,
        size: u64,
        required_flags: u32,
        forbidden_flags: u32,
    ) -> Option<&ProgramHeader> {
        let mappings = self
            .programs
            .iter()
            .filter(|program| {
                program.program_type == PT_LOAD
                    && program.contains_memory(address, size)
                    && program.flags & required_flags == required_flags
                    && program.flags & forbidden_flags == 0
            })
            .collect::<Vec<_>>();
        match mappings.as_slice() {
            [mapping] => Some(*mapping),
            _ => None,
        }
    }

    fn bytes_at_virtual_address<'a>(
        &self,
        bytes: &'a [u8],
        address: u64,
        size: u64,
    ) -> Result<&'a [u8], ProviderFinalPayloadGateError> {
        let range = self
            .file_range_at_virtual_address_with_bytes(bytes, address, size)
            .ok_or(ProviderFinalPayloadGateError::ProviderElfContractInvalid)?;
        checked_slice(
            range.bytes,
            range.start,
            usize::try_from(size)
                .map_err(|_| ProviderFinalPayloadGateError::ProviderElfContractInvalid)?,
        )
    }

    fn file_range_at_virtual_address_with_bytes<'a>(
        &self,
        bytes: &'a [u8],
        address: u64,
        size: u64,
    ) -> Option<ElfFileRange<'a>> {
        let mappings = self
            .programs
            .iter()
            .filter(|program| {
                program.program_type == PT_LOAD
                    && program.contains_memory(address, size)
                    && address
                        .checked_sub(program.virtual_address)
                        .and_then(|delta| program.offset.checked_add(delta))
                        .and_then(|offset| offset.checked_add(size))
                        .zip(program.file_end())
                        .is_some_and(|(end, file_end)| end <= file_end)
            })
            .collect::<Vec<_>>();
        let [mapping] = mappings.as_slice() else {
            return None;
        };
        let start = address
            .checked_sub(mapping.virtual_address)?
            .checked_add(mapping.offset)?;
        Some(ElfFileRange {
            bytes,
            start: usize::try_from(start).ok()?,
        })
    }
}

struct ElfFileRange<'a> {
    bytes: &'a [u8],
    start: usize,
}

fn parse_program_headers(
    bytes: &[u8],
    table_offset: u64,
    count: u16,
) -> Result<Vec<ProgramHeader>, ProviderFinalPayloadGateError> {
    let mut programs = Vec::with_capacity(usize::from(count));
    for index in 0..usize::from(count) {
        let offset = checked_table_entry(
            table_offset,
            index,
            PROGRAM_HEADER_SIZE,
            PROGRAM_HEADER_SIZE,
            bytes.len(),
        )?;
        programs.push(ProgramHeader {
            program_type: read_u32(bytes, offset)?,
            flags: read_u32(bytes, offset + 4)?,
            offset: read_u64(bytes, offset + 8)?,
            virtual_address: read_u64(bytes, offset + 16)?,
            file_size: read_u64(bytes, offset + 32)?,
            memory_size: read_u64(bytes, offset + 40)?,
            alignment: read_u64(bytes, offset + 48)?,
        });
    }
    Ok(programs)
}

fn validate_program_headers(
    bytes: &[u8],
    programs: &[ProgramHeader],
) -> Result<(), ProviderFinalPayloadGateError> {
    let mut loads = Vec::new();
    let mut stack_count = 0_usize;
    let mut dynamic_count = 0_usize;
    let mut interpreter_count = 0_usize;
    let mut relro_count = 0_usize;
    let mut tls_count = 0_usize;
    for program in programs {
        if program.flags & !(PF_R | PF_W | PF_X) != 0
            || program.file_size > program.memory_size
            || program
                .file_end()
                .is_none_or(|end| end > bytes.len() as u64)
            || program.memory_end().is_none()
            || (program.alignment > 1 && !program.alignment.is_power_of_two())
            || (program.alignment > 1
                && program.offset % program.alignment
                    != program.virtual_address % program.alignment)
        {
            return Err(ProviderFinalPayloadGateError::ElfMappingInvalid);
        }
        match program.program_type {
            PT_LOAD => {
                if program.memory_size == 0
                    || program.flags & PF_R == 0
                    || program.flags & (PF_W | PF_X) == (PF_W | PF_X)
                {
                    return Err(ProviderFinalPayloadGateError::ElfMappingInvalid);
                }
                loads.push(*program);
            }
            PT_DYNAMIC => dynamic_count += 1,
            PT_INTERP => interpreter_count += 1,
            PT_TLS => tls_count += 1,
            PT_GNU_RELRO => relro_count += 1,
            PT_GNU_STACK => {
                stack_count += 1;
                if program.flags & PF_X != 0 || program.file_size != 0 || program.memory_size != 0 {
                    return Err(ProviderFinalPayloadGateError::ElfMappingInvalid);
                }
            }
            _ => {}
        }
    }
    if loads.is_empty()
        || stack_count != 1
        || dynamic_count > 1
        || interpreter_count > 1
        || relro_count > 1
        || tls_count > 1
    {
        return Err(ProviderFinalPayloadGateError::ElfMappingInvalid);
    }
    loads.sort_by_key(|program| program.virtual_address);
    for pair in loads.windows(2) {
        if pair[0]
            .memory_end()
            .is_none_or(|end| end > pair[1].virtual_address)
        {
            return Err(ProviderFinalPayloadGateError::ElfMappingInvalid);
        }
    }
    for (index, left) in loads.iter().enumerate() {
        for right in loads.iter().skip(index + 1) {
            if left.file_size == 0 || right.file_size == 0 {
                continue;
            }
            let overlap = ranges_overlap(
                left.offset,
                left.file_end()
                    .ok_or(ProviderFinalPayloadGateError::ElfMappingInvalid)?,
                right.offset,
                right
                    .file_end()
                    .ok_or(ProviderFinalPayloadGateError::ElfMappingInvalid)?,
            );
            let left_bias = i128::from(left.virtual_address) - i128::from(left.offset);
            let right_bias = i128::from(right.virtual_address) - i128::from(right.offset);
            if overlap && left_bias != right_bias {
                return Err(ProviderFinalPayloadGateError::ElfMappingInvalid);
            }
        }
    }
    Ok(())
}

fn parse_section_headers(
    bytes: &[u8],
    table_offset: u64,
    count: u16,
    name_index: u16,
) -> Result<Vec<SectionHeader>, ProviderFinalPayloadGateError> {
    #[derive(Clone, Copy)]
    struct RawSection {
        name_offset: u32,
        section_type: u32,
        flags: u64,
        address: u64,
        offset: u64,
        size: u64,
        link: u32,
        info: u32,
        alignment: u64,
        entry_size: u64,
    }

    let mut raw = Vec::with_capacity(usize::from(count));
    for index in 0..usize::from(count) {
        let offset = checked_table_entry(
            table_offset,
            index,
            SECTION_HEADER_SIZE,
            SECTION_HEADER_SIZE,
            bytes.len(),
        )?;
        raw.push(RawSection {
            name_offset: read_u32(bytes, offset)?,
            section_type: read_u32(bytes, offset + 4)?,
            flags: read_u64(bytes, offset + 8)?,
            address: read_u64(bytes, offset + 16)?,
            offset: read_u64(bytes, offset + 24)?,
            size: read_u64(bytes, offset + 32)?,
            link: read_u32(bytes, offset + 40)?,
            info: read_u32(bytes, offset + 44)?,
            alignment: read_u64(bytes, offset + 48)?,
            entry_size: read_u64(bytes, offset + 56)?,
        });
    }
    let null = raw
        .first()
        .ok_or(ProviderFinalPayloadGateError::ElfMalformed)?;
    if null.name_offset != 0
        || null.section_type != SHT_NULL
        || null.flags != 0
        || null.address != 0
        || null.offset != 0
        || null.size != 0
        || null.link != 0
        || null.info != 0
        || null.alignment != 0
        || null.entry_size != 0
    {
        return Err(ProviderFinalPayloadGateError::ElfMalformed);
    }
    let names = raw
        .get(usize::from(name_index))
        .ok_or(ProviderFinalPayloadGateError::ElfMalformed)?;
    if names.section_type != SHT_STRTAB || names.size == 0 {
        return Err(ProviderFinalPayloadGateError::ElfMalformed);
    }
    let name_bytes = checked_slice_u64(bytes, names.offset, names.size)?;
    if name_bytes.first() != Some(&0) || name_bytes.last() != Some(&0) {
        return Err(ProviderFinalPayloadGateError::ElfMalformed);
    }
    raw.into_iter()
        .enumerate()
        .map(|(index, section)| {
            Ok(SectionHeader {
                index,
                name: read_c_string(name_bytes, u64::from(section.name_offset))?,
                section_type: section.section_type,
                flags: section.flags,
                address: section.address,
                offset: section.offset,
                size: section.size,
                link: section.link,
                info: section.info,
                alignment: section.alignment,
                entry_size: section.entry_size,
            })
        })
        .collect()
}

fn validate_section_headers(
    bytes: &[u8],
    programs: &[ProgramHeader],
    sections: &[SectionHeader],
) -> Result<(), ProviderFinalPayloadGateError> {
    for section in sections.iter().skip(1) {
        if (section.alignment > 1 && !section.alignment.is_power_of_two())
            || (section.entry_size != 0
                && (section.entry_size > section.size || section.size % section.entry_size != 0))
            || (section.link != 0 && section.link as usize >= sections.len())
            || section.memory_end().is_none()
        {
            return Err(ProviderFinalPayloadGateError::ElfMalformed);
        }
        if section.section_type != SHT_NOBITS
            && section
                .file_end()
                .is_none_or(|end| end > bytes.len() as u64)
        {
            return Err(ProviderFinalPayloadGateError::ElfMalformed);
        }
        if section.flags & SHF_ALLOC == 0 || section.size == 0 {
            continue;
        }
        let mappings = programs
            .iter()
            .filter(|program| {
                if program.program_type != PT_LOAD
                    || program.flags & PF_R == 0
                    || section.flags & SHF_WRITE != 0 && program.flags & PF_W == 0
                    || section.flags & SHF_EXECINSTR != 0 && program.flags & PF_X == 0
                {
                    return false;
                }
                if section.section_type == SHT_NOBITS {
                    program.contains_memory(section.address, section.size)
                } else {
                    program.contains_file_mapping(section.address, section.offset, section.size)
                }
            })
            .count();
        if mappings != 1 {
            return Err(ProviderFinalPayloadGateError::ElfMappingInvalid);
        }
    }
    Ok(())
}

fn parse_and_validate_symbols(
    bytes: &[u8],
    sections: &[SectionHeader],
) -> Result<Vec<ElfSymbol>, ProviderFinalPayloadGateError> {
    let symbol_tables = sections
        .iter()
        .filter(|section| matches!(section.section_type, SHT_SYMTAB | SHT_DYNSYM))
        .collect::<Vec<_>>();
    if symbol_tables
        .iter()
        .filter(|section| section.section_type == SHT_SYMTAB)
        .count()
        > 1
        || symbol_tables
            .iter()
            .filter(|section| section.section_type == SHT_DYNSYM)
            .count()
            > 1
    {
        return Err(ProviderFinalPayloadGateError::ElfMalformed);
    }
    let mut symbols = Vec::new();
    for table in symbol_tables {
        if table.entry_size != SYMBOL_ENTRY_SIZE as u64
            || table.size % SYMBOL_ENTRY_SIZE as u64 != 0
            || table.size / SYMBOL_ENTRY_SIZE as u64 > MAX_SYMBOLS as u64
        {
            return Err(ProviderFinalPayloadGateError::ElfMalformed);
        }
        let strings = sections
            .get(table.link as usize)
            .ok_or(ProviderFinalPayloadGateError::ElfMalformed)?;
        if strings.section_type != SHT_STRTAB {
            return Err(ProviderFinalPayloadGateError::ElfMalformed);
        }
        let string_bytes = section_bytes(bytes, strings)?;
        if string_bytes.first() != Some(&0) || string_bytes.last() != Some(&0) {
            return Err(ProviderFinalPayloadGateError::ElfMalformed);
        }
        let count = usize::try_from(table.size / SYMBOL_ENTRY_SIZE as u64)
            .map_err(|_| ProviderFinalPayloadGateError::ElfMalformed)?;
        if table.info as usize > count {
            return Err(ProviderFinalPayloadGateError::ElfMalformed);
        }
        for index in 0..count {
            let offset = usize::try_from(table.offset)
                .ok()
                .and_then(|base| {
                    index
                        .checked_mul(SYMBOL_ENTRY_SIZE)
                        .and_then(|delta| base.checked_add(delta))
                })
                .ok_or(ProviderFinalPayloadGateError::ElfMalformed)?;
            let name = read_c_string(string_bytes, u64::from(read_u32(bytes, offset)?))?;
            let info = *checked_slice(bytes, offset + 4, 1)?
                .first()
                .ok_or(ProviderFinalPayloadGateError::ElfMalformed)?;
            let other = *checked_slice(bytes, offset + 5, 1)?
                .first()
                .ok_or(ProviderFinalPayloadGateError::ElfMalformed)?;
            let section_index = read_u16(bytes, offset + 6)?;
            let value = read_u64(bytes, offset + 8)?;
            let size = read_u64(bytes, offset + 16)?;
            let binding = info >> 4;
            let symbol_type = info & 0x0f;
            let visibility = other & 0x03;
            if other & !0x03 != 0
                || section_index == SHN_XINDEX
                || index < table.info as usize && binding != 0
                || index >= table.info as usize && index != 0 && binding == 0
            {
                return Err(ProviderFinalPayloadGateError::ElfMalformed);
            }
            if index == 0
                && (!name.is_empty()
                    || info != 0
                    || other != 0
                    || section_index != SHN_UNDEF
                    || value != 0
                    || size != 0)
            {
                return Err(ProviderFinalPayloadGateError::ElfMalformed);
            }
            if !matches!(section_index, SHN_UNDEF | SHN_ABS | SHN_COMMON) {
                let section = sections
                    .get(usize::from(section_index))
                    .ok_or(ProviderFinalPayloadGateError::ElfMalformed)?;
                if section.flags & SHF_ALLOC != 0
                    && symbol_type != 3
                    && (value < section.address
                        || value
                            .checked_add(size)
                            .zip(section.memory_end())
                            .is_none_or(|(end, section_end)| end > section_end))
                {
                    return Err(ProviderFinalPayloadGateError::ElfMalformed);
                }
            }
            symbols.push(ElfSymbol {
                table_type: table.section_type,
                name,
                binding,
                symbol_type,
                visibility,
                section_index,
                value,
                size,
            });
        }
    }
    Ok(symbols)
}

fn section_bytes<'a>(
    bytes: &'a [u8],
    section: &SectionHeader,
) -> Result<&'a [u8], ProviderFinalPayloadGateError> {
    if section.section_type == SHT_NOBITS {
        return Err(ProviderFinalPayloadGateError::ElfMalformed);
    }
    checked_slice_u64(bytes, section.offset, section.size)
}

fn symbol_matches(
    symbol: &ElfSymbol,
    binding: u8,
    symbol_type: u8,
    visibility: u8,
    value: u64,
    size: u64,
) -> bool {
    symbol.binding == binding
        && symbol.symbol_type == symbol_type
        && symbol.visibility == visibility
        && symbol.section_index != SHN_UNDEF
        && symbol.value == value
        && symbol.size == size
}

fn validate_aarch64_controlled_entry(
    bytes: &[u8],
    entry_address: u64,
    bootstrap_address: u64,
    original_start_address: u64,
) -> bool {
    if bytes.len() != 32 {
        return false;
    }
    let words = bytes
        .chunks_exact(4)
        .map(|chunk| {
            u32::from_le_bytes(
                chunk
                    .try_into()
                    .expect("chunks_exact yields four-byte instructions"),
            )
        })
        .collect::<Vec<_>>();
    words[0] == 0xa9bf_7bfd
        && words[1] == 0xa9bf_07e0
        && words[2] == 0xa9bf_0fe2
        && words[3] & 0xfc00_0000 == 0x9400_0000
        && branch_target(entry_address + 12, words[3]) == Some(bootstrap_address)
        && words[4] == 0xa8c1_0fe2
        && words[5] == 0xa8c1_07e0
        && words[6] == 0xa8c1_7bfd
        && words[7] & 0xfc00_0000 == 0x1400_0000
        && branch_target(entry_address + 28, words[7]) == Some(original_start_address)
}

fn branch_target(program_counter: u64, instruction: u32) -> Option<u64> {
    let immediate = i64::from(((instruction & 0x03ff_ffff) << 6) as i32 >> 6) << 2;
    if immediate >= 0 {
        program_counter.checked_add(immediate as u64)
    } else {
        program_counter.checked_sub(immediate.unsigned_abs())
    }
}

fn exact_filter_bytes(instructions: &[ClassicBpfInstruction]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(instructions.len() * 8);
    for instruction in instructions {
        bytes.extend_from_slice(&instruction.code.to_le_bytes());
        bytes.push(instruction.jump_true);
        bytes.push(instruction.jump_false);
        bytes.extend_from_slice(&instruction.value.to_le_bytes());
    }
    bytes
}

fn ranges_overlap(left_start: u64, left_end: u64, right_start: u64, right_end: u64) -> bool {
    left_start < right_end && right_start < left_end
}

fn checked_table_range(
    offset: u64,
    count: usize,
    entry_size: usize,
    file_size: usize,
) -> Result<(), ProviderFinalPayloadGateError> {
    let offset =
        usize::try_from(offset).map_err(|_| ProviderFinalPayloadGateError::ElfMalformed)?;
    let size = count
        .checked_mul(entry_size)
        .ok_or(ProviderFinalPayloadGateError::ElfMalformed)?;
    if offset.checked_add(size).is_none_or(|end| end > file_size) {
        return Err(ProviderFinalPayloadGateError::ElfMalformed);
    }
    Ok(())
}

fn checked_table_entry(
    table_offset: u64,
    index: usize,
    entry_size: usize,
    required_size: usize,
    file_size: usize,
) -> Result<usize, ProviderFinalPayloadGateError> {
    let base =
        usize::try_from(table_offset).map_err(|_| ProviderFinalPayloadGateError::ElfMalformed)?;
    let offset = index
        .checked_mul(entry_size)
        .and_then(|delta| base.checked_add(delta))
        .ok_or(ProviderFinalPayloadGateError::ElfMalformed)?;
    if entry_size < required_size
        || offset
            .checked_add(required_size)
            .is_none_or(|end| end > file_size)
    {
        return Err(ProviderFinalPayloadGateError::ElfMalformed);
    }
    Ok(offset)
}

fn checked_slice(
    bytes: &[u8],
    offset: usize,
    size: usize,
) -> Result<&[u8], ProviderFinalPayloadGateError> {
    bytes
        .get(
            offset
                ..offset
                    .checked_add(size)
                    .ok_or(ProviderFinalPayloadGateError::ElfMalformed)?,
        )
        .ok_or(ProviderFinalPayloadGateError::ElfMalformed)
}

fn checked_slice_u64(
    bytes: &[u8],
    offset: u64,
    size: u64,
) -> Result<&[u8], ProviderFinalPayloadGateError> {
    checked_slice(
        bytes,
        usize::try_from(offset).map_err(|_| ProviderFinalPayloadGateError::ElfMalformed)?,
        usize::try_from(size).map_err(|_| ProviderFinalPayloadGateError::ElfMalformed)?,
    )
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, ProviderFinalPayloadGateError> {
    Ok(u16::from_le_bytes(
        checked_slice(bytes, offset, 2)?
            .try_into()
            .map_err(|_| ProviderFinalPayloadGateError::ElfMalformed)?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ProviderFinalPayloadGateError> {
    Ok(u32::from_le_bytes(
        checked_slice(bytes, offset, 4)?
            .try_into()
            .map_err(|_| ProviderFinalPayloadGateError::ElfMalformed)?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, ProviderFinalPayloadGateError> {
    Ok(u64::from_le_bytes(
        checked_slice(bytes, offset, 8)?
            .try_into()
            .map_err(|_| ProviderFinalPayloadGateError::ElfMalformed)?,
    ))
}

fn read_c_string(bytes: &[u8], offset: u64) -> Result<String, ProviderFinalPayloadGateError> {
    let offset =
        usize::try_from(offset).map_err(|_| ProviderFinalPayloadGateError::ElfMalformed)?;
    let tail = bytes
        .get(offset..)
        .ok_or(ProviderFinalPayloadGateError::ElfMalformed)?;
    let length = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(ProviderFinalPayloadGateError::ElfMalformed)?;
    std::str::from_utf8(&tail[..length])
        .map(str::to_owned)
        .map_err(|_| ProviderFinalPayloadGateError::ElfMalformed)
}

fn sha256_digest(bytes: &[u8]) -> Digest {
    let bytes: [u8; 32] = Sha256::digest(bytes).into();
    Digest::new(FixedBytes32::new(bytes).expect("SHA-256 cannot be all zero in reviewed inputs"))
}

fn domain_digest(domain: &[u8], fields: &[&[u8]]) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for field in fields {
        hasher.update(
            u64::try_from(field.len())
                .expect("bounded digest field")
                .to_be_bytes(),
        );
        hasher.update(field);
    }
    let bytes: [u8; 32] = hasher.finalize().into();
    Digest::new(FixedBytes32::new(bytes).expect("domain-separated SHA-256 cannot be all zero"))
}

const fn provider_discriminator(provider: Provider) -> u8 {
    match provider {
        Provider::Codex => 1,
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _, symlink};
    use std::path::Path;

    use serde_json::Value;
    use tempfile::TempDir;

    use super::*;

    const _: () = {
        assert!(SOURCE_UNTRUSTED_BUILD_CLAIM_PARSER_IMPLEMENTED);
        assert!(SOURCE_RETAINED_ELF_STRUCTURAL_INSPECTION_IMPLEMENTED);
        assert!(SOURCE_FROZEN_EXACT_SOURCE_BUILDER_RECIPE_IMPLEMENTED);
        assert!(SOURCE_NONAUTHORIZING_TWO_BUILDER_RECEIPT_PRODUCER_IMPLEMENTED);
        assert!(!SOURCE_AUTHENTICATED_BUILD_RECEIPT_IMPLEMENTED);
        assert!(!SOURCE_FIXED_ROOT_FINAL_ELF_CUSTODY_IMPLEMENTED);
        assert!(!SOURCE_OBJECT_TO_FINAL_RANGE_PROVENANCE_IMPLEMENTED);
        assert!(!PRODUCT_PROVIDER_BUILD_RECEIPT_SOURCE_AVAILABLE);
        assert!(!PRODUCT_PROVIDER_FINAL_ELF_GATE_WIRED);
        assert!(!PRODUCT_PROVIDER_PAYLOAD_RECIPE_WIRED);
        assert!(!PRODUCT_LISTENER_BACKEND_AVAILABLE);
        assert!(!PRODUCT_EFFECT_ADMISSION_AVAILABLE);
        assert!(!CONFERS_EFFECT_AUTHORITY);
    };

    const CODEX_ENTRY_OFFSET: usize = 0x1000;
    const CODEX_FILTER_OFFSET: usize = 0x2000;
    const CODEX_PROGRAM_OFFSET: usize = ELF_HEADER_SIZE;
    const CODEX_SECTION_OFFSET: usize = 0x3000;
    struct Fixture {
        bytes: Vec<u8>,
        claim: UntrustedProviderFinalPayloadClaimV1,
    }

    fn open_candidate_for_test_result(path: &Path) -> Result<File, ProviderFinalPayloadGateError> {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| ProviderFinalPayloadGateError::RetainedOpenFailed)
    }

    fn open_candidate_for_test(path: &Path) -> File {
        open_candidate_for_test_result(path).expect("open retained structural candidate")
    }

    #[test]
    fn canonical_untrusted_receipt_and_retained_codex_structure_accept_exact_candidate() {
        let fixture = codex_fixture();
        let compact = serde_json::to_vec(&fixture.claim).expect("claim JSON");
        let pretty = serde_json::to_vec_pretty(&fixture.claim).expect("pretty claim JSON");
        let (_, compact_digest) =
            UntrustedProviderFinalPayloadClaimV1::parse_and_validate_untrusted_shape(&compact)
                .expect("valid untrusted claim");
        let (_, pretty_digest) =
            UntrustedProviderFinalPayloadClaimV1::parse_and_validate_untrusted_shape(&pretty)
                .expect("valid untrusted claim");
        assert_eq!(compact_digest, pretty_digest);

        let directory = TempDir::new().expect("temporary directory");
        let path = directory.path().join("codex");
        fs::write(&path, &fixture.bytes).expect("write fixture");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o555))
            .expect("set executable permissions");
        let candidate = inspect_retained_provider_final_elf_candidate(
            open_candidate_for_test(&path),
            &compact,
            RetainedFilePolicy {
                expected_uid: unsafe { libc::geteuid() },
                expected_gid: unsafe { libc::getegid() },
                require_root_immutable_or_read_only_mount: false,
            },
        )
        .expect("retained candidate passes structural checks");
        assert_eq!(candidate.provider, Provider::Codex);
        assert_eq!(candidate.final_elf_sha256, sha256_digest(&fixture.bytes));
        assert_ne!(
            candidate.untrusted_claim_sha256,
            candidate.structural_candidate_sha256
        );
    }

    #[test]
    fn codex_receipt_accepts_zero_sized_musl_start_symbol_but_not_unaligned_size() {
        let fixture = codex_fixture();
        let ProviderElfExpectation::CodexControlledEntry(mut expectation) =
            fixture.claim.elf_expectation;
        expectation.original_start_size = 0;
        assert_eq!(expectation.validate(), Ok(()));

        expectation.original_start_size = 2;
        assert_eq!(
            expectation.validate(),
            Err(ProviderFinalPayloadGateError::ReceiptInvalid)
        );
    }

    #[test]
    fn receipt_rejects_unknown_fields_pins_overrides_response_bypass_and_cross_field_drift() {
        let fixture = codex_fixture();
        let mut value = serde_json::to_value(&fixture.claim).expect("claim value");
        value
            .as_object_mut()
            .expect("receipt object")
            .insert("unknown_authority".to_owned(), Value::Bool(false));
        assert_eq!(
            UntrustedProviderFinalPayloadClaimV1::parse_and_validate_untrusted_shape(
                &serde_json::to_vec(&value).expect("JSON"),
            )
            .unwrap_err(),
            ProviderFinalPayloadGateError::ReceiptMalformed
        );

        for mutate in [
            mutate_wrong_source_tree as fn(&mut UntrustedProviderFinalPayloadClaimV1),
            mutate_fixture_define,
            mutate_response_file_override,
            mutate_builder_flag_environment,
            mutate_forbidden_environment_injection,
            mutate_reproducibility_output,
            mutate_missing_core_input,
            mutate_unrelated_original_start_crt,
            mutate_wrong_final_name,
        ] {
            let mut claim = fixture.claim.clone();
            mutate(&mut claim);
            assert!(
                UntrustedProviderFinalPayloadClaimV1::parse_and_validate_untrusted_shape(
                    &serde_json::to_vec(&claim).expect("JSON"),
                )
                .is_err(),
                "mutation unexpectedly accepted"
            );
        }
    }

    #[test]
    fn retained_intake_rejects_symlink_and_multiple_links() {
        let fixture = codex_fixture();
        let claim = serde_json::to_vec(&fixture.claim).expect("claim JSON");
        let directory = TempDir::new().expect("temporary directory");
        let original = directory.path().join("codex");
        let link = directory.path().join("codex-link");
        fs::write(&original, &fixture.bytes).expect("write fixture");
        fs::set_permissions(&original, fs::Permissions::from_mode(0o555))
            .expect("set executable permissions");
        symlink(&original, &link).expect("create symlink");
        let policy = RetainedFilePolicy {
            expected_uid: unsafe { libc::geteuid() },
            expected_gid: unsafe { libc::getegid() },
            require_root_immutable_or_read_only_mount: false,
        };
        assert_eq!(
            open_candidate_for_test_result(&link)
                .and_then(|file| inspect_retained_provider_final_elf_candidate(
                    file, &claim, policy
                ))
                .unwrap_err(),
            ProviderFinalPayloadGateError::RetainedOpenFailed
        );
        fs::remove_file(&link).expect("remove symlink");
        fs::hard_link(&original, &link).expect("create hard link");
        assert_eq!(
            inspect_retained_provider_final_elf_candidate(
                open_candidate_for_test(&original),
                &claim,
                policy,
            )
            .unwrap_err(),
            ProviderFinalPayloadGateError::RetainedCustodyInvalid
        );
    }

    #[test]
    fn generic_and_codex_mutations_fail_closed() {
        let fixture = codex_fixture();
        assert_candidate_contract(&fixture);
        let mutations = [
            (18_usize, vec![0_u8, 0_u8]),
            (
                CODEX_PROGRAM_OFFSET + PROGRAM_HEADER_SIZE + 4,
                (PF_R | PF_W | PF_X).to_le_bytes().to_vec(),
            ),
            (
                CODEX_PROGRAM_OFFSET + 3 * PROGRAM_HEADER_SIZE + 4,
                (PF_R | PF_W | PF_X).to_le_bytes().to_vec(),
            ),
            (
                CODEX_SECTION_OFFSET + 2 * SECTION_HEADER_SIZE + 24,
                0x2100_u64.to_le_bytes().to_vec(),
            ),
        ];
        for (offset, replacement) in mutations {
            let mut changed = fixture.bytes.clone();
            changed[offset..offset + replacement.len()].copy_from_slice(&replacement);
            assert!(ParsedElf::parse_and_validate(&changed).is_err());
        }

        for instruction in 0..8 {
            let mut changed = fixture.bytes.clone();
            changed[CODEX_ENTRY_OFFSET + instruction * 4] ^= 1;
            assert_provider_contract_rejected(&changed, &fixture.claim);
        }
        let mut changed = fixture.bytes.clone();
        changed[CODEX_FILTER_OFFSET] ^= 1;
        assert_provider_contract_rejected(&changed, &fixture.claim);
    }

    fn assert_candidate_contract(fixture: &Fixture) {
        let claim_bytes = serde_json::to_vec(&fixture.claim).expect("claim JSON");
        let (claim, _) =
            UntrustedProviderFinalPayloadClaimV1::parse_and_validate_untrusted_shape(&claim_bytes)
                .expect("valid untrusted claim");
        let parsed = ParsedElf::parse_and_validate(&fixture.bytes).expect("valid ELF");
        parsed
            .verify_provider_contract(&fixture.bytes, &claim)
            .expect("valid provider contract");
    }

    fn assert_provider_contract_rejected(
        bytes: &[u8],
        claim: &UntrustedProviderFinalPayloadClaimV1,
    ) {
        if let Ok(parsed) = ParsedElf::parse_and_validate(bytes) {
            assert!(parsed.verify_provider_contract(bytes, claim).is_err());
        }
    }

    fn codex_fixture() -> Fixture {
        let mut bytes = vec![0_u8; 0x3200];
        let filter = exact_filter_bytes(&exact_aarch64_provider_seccomp_filter());
        let text_address = 0x401000_u64;
        let core_address = text_address + 0x40;
        let start_address = text_address + 0x60;
        write_elf_header(
            &mut bytes,
            ET_EXEC,
            text_address,
            4,
            CODEX_SECTION_OFFSET as u64,
            6,
            5,
        );
        write_program_header(
            &mut bytes, 0, PT_LOAD, PF_R, 0, 0x400000, 0x400, 0x400, 0x1000,
        );
        write_program_header(
            &mut bytes,
            1,
            PT_LOAD,
            PF_R | PF_X,
            0x1000,
            text_address,
            0x80,
            0x80,
            0x1000,
        );
        write_program_header(
            &mut bytes,
            2,
            PT_LOAD,
            PF_R,
            0x2000,
            0x402000,
            filter.len() as u64,
            filter.len() as u64,
            0x1000,
        );
        write_program_header(&mut bytes, 3, PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 0, 16);

        let entry = aarch64_entry_bytes(text_address, core_address, start_address);
        bytes[CODEX_ENTRY_OFFSET..CODEX_ENTRY_OFFSET + entry.len()].copy_from_slice(&entry);
        write_u32_at(&mut bytes, CODEX_ENTRY_OFFSET + 0x40, 0xd65f_03c0);
        write_u32_at(&mut bytes, CODEX_ENTRY_OFFSET + 0x60, 0xd65f_03c0);
        bytes[CODEX_FILTER_OFFSET..CODEX_FILTER_OFFSET + filter.len()].copy_from_slice(&filter);

        let strings = b"\0trillionnium_provider_post_final_exec_entry\0trillionnium_provider_post_final_exec_bootstrap\0_start\0";
        let entry_name = string_offset(strings, "trillionnium_provider_post_final_exec_entry");
        let core_name = string_offset(strings, "trillionnium_provider_post_final_exec_bootstrap");
        let start_name = string_offset(strings, "_start");
        let symbol_offset = 0x2800;
        write_symbol(
            &mut bytes,
            symbol_offset + SYMBOL_ENTRY_SIZE,
            entry_name,
            STB_GLOBAL,
            STT_FUNC,
            STV_HIDDEN,
            1,
            text_address,
            32,
        );
        write_symbol(
            &mut bytes,
            symbol_offset + 2 * SYMBOL_ENTRY_SIZE,
            core_name,
            STB_GLOBAL,
            STT_FUNC,
            STV_HIDDEN,
            1,
            core_address,
            4,
        );
        write_symbol(
            &mut bytes,
            symbol_offset + 3 * SYMBOL_ENTRY_SIZE,
            start_name,
            STB_GLOBAL,
            STT_FUNC,
            STV_DEFAULT,
            1,
            start_address,
            4,
        );
        bytes[0x2860..0x2860 + strings.len()].copy_from_slice(strings);
        let section_names =
            b"\0.text\0.trillionnium.provider_filter\0.symtab\0.strtab\0.shstrtab\0";
        bytes[0x2900..0x2900 + section_names.len()].copy_from_slice(section_names);
        write_section_header(
            &mut bytes,
            CODEX_SECTION_OFFSET,
            1,
            string_offset(section_names, ".text"),
            SHT_PROGBITS,
            SHF_ALLOC | SHF_EXECINSTR,
            text_address,
            0x1000,
            0x80,
            0,
            0,
            4,
            0,
        );
        write_section_header(
            &mut bytes,
            CODEX_SECTION_OFFSET,
            2,
            string_offset(section_names, ".trillionnium.provider_filter"),
            SHT_PROGBITS,
            SHF_ALLOC,
            0x402000,
            0x2000,
            filter.len() as u64,
            0,
            0,
            8,
            0,
        );
        write_section_header(
            &mut bytes,
            CODEX_SECTION_OFFSET,
            3,
            string_offset(section_names, ".symtab"),
            SHT_SYMTAB,
            0,
            0,
            symbol_offset as u64,
            (4 * SYMBOL_ENTRY_SIZE) as u64,
            4,
            1,
            8,
            SYMBOL_ENTRY_SIZE as u64,
        );
        write_section_header(
            &mut bytes,
            CODEX_SECTION_OFFSET,
            4,
            string_offset(section_names, ".strtab"),
            SHT_STRTAB,
            0,
            0,
            0x2860,
            strings.len() as u64,
            0,
            0,
            1,
            0,
        );
        write_section_header(
            &mut bytes,
            CODEX_SECTION_OFFSET,
            5,
            string_offset(section_names, ".shstrtab"),
            SHT_STRTAB,
            0,
            0,
            0x2900,
            section_names.len() as u64,
            0,
            0,
            1,
            0,
        );

        let expectation =
            ProviderElfExpectation::CodexControlledEntry(CodexControlledEntryExpectation {
                controlled_entry_address: text_address,
                controlled_entry_size: 32,
                controlled_entry_sha256: sha256_digest(&entry),
                bootstrap_core_address: core_address,
                bootstrap_core_size: 4,
                original_start_address: start_address,
                original_start_size: 4,
                original_start_crt_object: artifact("build/crt1.o", b"crt1"),
            });
        let claim = claim_for(&bytes, expectation);
        Fixture { bytes, claim }
    }

    fn claim_for(
        final_elf_bytes: &[u8],
        elf_expectation: ProviderElfExpectation,
    ) -> UntrustedProviderFinalPayloadClaimV1 {
        let core = artifact("build/provider-post-exec-bootstrap.o", b"core-object");
        let mechanism = artifact("build/provider-post-exec-entry.o", b"mechanism-object");
        let ProviderElfExpectation::CodexControlledEntry(expectation) = &elf_expectation;
        let crt = expectation.original_start_crt_object.clone();
        let link_map = artifact("build/final.map", b"link-map");
        let closure_manifest = artifact("build/closure.json", b"closure");
        let final_name = "/out/provider-final/codex";
        let source = ExactSourceReceipt {
            repository_url: CODEX_SOURCE_URL.to_owned(),
            version: "0.144.1".to_owned(),
            annotated_tag: CODEX_SOURCE_TAG.to_owned(),
            annotated_tag_object_sha1: CODEX_TAG_OBJECT_SHA1.to_owned(),
            dereferenced_commit_sha1: CODEX_SOURCE_COMMIT_SHA1.to_owned(),
            source_tree_sha1: CODEX_SOURCE_TREE_SHA1.to_owned(),
            source_archive: None,
            clean_tree: true,
            lockfiles: vec![artifact("source/Cargo.lock", b"cargo-lock")],
            patched_sources: vec![artifact(
                "patches/provider-bootstrap.patch",
                b"bootstrap-patch",
            )],
        };
        let builder_environment = vec![
            EnvironmentBinding {
                name: "PATH".to_owned(),
                value: "/opt/toolchain/bin:/usr/bin".to_owned(),
            },
            EnvironmentBinding {
                name: "LC_ALL".to_owned(),
                value: "C".to_owned(),
            },
            EnvironmentBinding {
                name: "TZ".to_owned(),
                value: "UTC".to_owned(),
            },
            EnvironmentBinding {
                name: "SOURCE_DATE_EPOCH".to_owned(),
                value: "1782146701".to_owned(),
            },
        ];
        let mut claim = UntrustedProviderFinalPayloadClaimV1 {
            schema: UNTRUSTED_CLAIM_SCHEMA.to_owned(),
            provider: Provider::Codex,
            target_architecture: "aarch64-unknown-linux".to_owned(),
            source,
            bootstrap: BootstrapBuildReceipt {
                public_header: artifact(
                    "bootstrap/trillionnium_provider_post_exec_bootstrap.h",
                    b"header",
                ),
                freestanding_core_source: artifact(
                    "bootstrap/provider_post_exec_bootstrap.c",
                    b"core-source",
                ),
                controlled_entry_source: Some(artifact(
                    "bootstrap/provider_post_exec_entry.S",
                    b"controlled-entry-source",
                )),
                core: BootstrapObjectClosureReceipt {
                    object: core.clone(),
                    relocation_manifest: artifact(
                        "build/provider-post-exec-bootstrap.relocations",
                        b"relocations",
                    ),
                    undefined_symbol_count: 0,
                    tls_section_count: 0,
                    plt_section_count: 0,
                    got_section_count: 0,
                    ifunc_symbol_count: 0,
                    init_dependency_count: 0,
                    preinit_dependency_count: 0,
                    stack_protector_reference_count: 0,
                    unexpected_relocation_count: 0,
                },
                mechanism_object: mechanism.clone(),
                exact_filter_sha256: seccomp_filter_sha256(&exact_aarch64_provider_seccomp_filter()),
            },
            build: BuildInvocationReceipt {
                working_directory: "/build/provider-final".to_owned(),
                environment: builder_environment,
                compiler: artifact("/opt/toolchain/bin/aarch64-linux-gnu-gcc", b"compiler"),
                assembler: artifact("/opt/toolchain/bin/aarch64-linux-gnu-as", b"assembler"),
                linker: artifact("/opt/toolchain/bin/aarch64-linux-gnu-ld", b"linker"),
                sysroot_manifest: artifact("build/sysroot-manifest.json", b"sysroot"),
                crt_objects: vec![crt.clone()],
                compiler_arguments: vec![
                    "--target=aarch64-unknown-linux".to_owned(),
                    "-ffreestanding".to_owned(),
                    "-fno-stack-protector".to_owned(),
                ],
                linker_arguments: vec![
                    "@build/link.rsp".to_owned(),
                    "-Wl,-z,now".to_owned(),
                    "-Wl,-z,noexecstack".to_owned(),
                ],
                response_files: vec![ResponseFileReceipt {
                    file: artifact("build/link.rsp", b"link-response"),
                    expanded_arguments: vec!["-static".to_owned()],
                }],
                dependency_manifest: artifact("build/dependencies.json", b"dependencies"),
                dependencies: vec![
                    artifact("source/provider.c", b"provider-source"),
                    artifact("sysroot/include/stdint.h", b"stdint"),
                ],
                preprocessed_source: artifact("build/provider.i", b"preprocessed-source"),
                macro_dump: artifact("build/provider.macros", b"macro-dump"),
                externally_supplied_definitions: vec![
                    "TRILLIONNIUM_EXPECTED_UID".to_owned(),
                    "TRILLIONNIUM_EXPECTED_GID".to_owned(),
                ],
                ordered_input_objects: vec![crt, mechanism.clone(), core.clone()],
                link_map: link_map.clone(),
                closure_manifest: closure_manifest.clone(),
            },
            reproducibility: TwoBuilderReproducibilityReceipt {
                builders: vec![
                    BuilderIdentityReceipt {
                        builder_id: "builder-a".to_owned(),
                        builder_image: artifact("builders/a.image", b"builder-a-image"),
                        builder_attestation_sha256: digest_byte(0xa1),
                    },
                    BuilderIdentityReceipt {
                        builder_id: "builder-b".to_owned(),
                        builder_image: artifact("builders/b.image", b"builder-b-image"),
                        builder_attestation_sha256: digest_byte(0xb1),
                    },
                ],
                outputs: vec![
                    ReproducedOutputReceipt {
                        final_elf_sha256: sha256_digest(final_elf_bytes),
                        core_object_sha256: core.sha256,
                        mechanism_object_sha256: mechanism.sha256,
                        link_map_sha256: link_map.sha256,
                        closure_manifest_sha256: closure_manifest.sha256,
                        normalized_inputs_sha256: digest_byte(1),
                    };
                    2
                ],
            },
            final_elf: HashedArtifact {
                logical_path: final_name.to_owned(),
                byte_length: final_elf_bytes.len() as u64,
                sha256: sha256_digest(final_elf_bytes),
            },
            elf_expectation,
            product_active: false,
            listener_backend_wired: false,
            admission_wired: false,
            confers_effect_authority: false,
        };
        refresh_normalized_outputs(&mut claim);
        claim.validate().expect("fixture claim validates");
        claim
    }

    fn refresh_normalized_outputs(claim: &mut UntrustedProviderFinalPayloadClaimV1) {
        let normalized = claim
            .normalized_inputs_sha256()
            .expect("normalized claim inputs");
        for output in &mut claim.reproducibility.outputs {
            output.normalized_inputs_sha256 = normalized;
        }
    }

    fn mutate_wrong_source_tree(claim: &mut UntrustedProviderFinalPayloadClaimV1) {
        claim.source.source_tree_sha1 = "1111111111111111111111111111111111111111".to_owned();
        refresh_normalized_outputs(claim);
    }

    fn mutate_fixture_define(claim: &mut UntrustedProviderFinalPayloadClaimV1) {
        claim
            .build
            .externally_supplied_definitions
            .push("FAULT_WRONG_FILTER".to_owned());
        refresh_normalized_outputs(claim);
    }

    fn mutate_response_file_override(claim: &mut UntrustedProviderFinalPayloadClaimV1) {
        claim.build.response_files[0]
            .expanded_arguments
            .push("-include".to_owned());
        refresh_normalized_outputs(claim);
    }

    fn mutate_builder_flag_environment(claim: &mut UntrustedProviderFinalPayloadClaimV1) {
        claim.build.environment.push(EnvironmentBinding {
            name: "CFLAGS".to_owned(),
            value: "-DTRILLIONNIUM_BOOTSTRAP_STOP=attacker".to_owned(),
        });
        refresh_normalized_outputs(claim);
    }

    fn mutate_forbidden_environment_injection(claim: &mut UntrustedProviderFinalPayloadClaimV1) {
        claim.build.environment.push(EnvironmentBinding {
            name: "NODE_OPTIONS".to_owned(),
            value: "--require=/tmp/injected.js".to_owned(),
        });
        refresh_normalized_outputs(claim);
    }

    fn mutate_reproducibility_output(claim: &mut UntrustedProviderFinalPayloadClaimV1) {
        claim.reproducibility.outputs[1].final_elf_sha256 = digest_byte(0xee);
    }

    fn mutate_missing_core_input(claim: &mut UntrustedProviderFinalPayloadClaimV1) {
        let core = claim.bootstrap.core.object.clone();
        claim
            .build
            .ordered_input_objects
            .retain(|artifact| artifact != &core);
        refresh_normalized_outputs(claim);
    }

    fn mutate_unrelated_original_start_crt(claim: &mut UntrustedProviderFinalPayloadClaimV1) {
        let ProviderElfExpectation::CodexControlledEntry(expectation) = &mut claim.elf_expectation;
        expectation.original_start_crt_object = artifact("build/unrelated-crt.o", b"other");
        refresh_normalized_outputs(claim);
    }

    fn mutate_wrong_final_name(claim: &mut UntrustedProviderFinalPayloadClaimV1) {
        claim.final_elf.logical_path = "/out/provider-final/not-codex".to_owned();
    }

    fn artifact(path: &str, bytes: &[u8]) -> HashedArtifact {
        HashedArtifact {
            logical_path: path.to_owned(),
            byte_length: bytes.len() as u64,
            sha256: sha256_digest(bytes),
        }
    }

    fn digest_byte(byte: u8) -> Digest {
        Digest::new(FixedBytes32::new([byte; 32]).expect("nonzero digest fixture"))
    }

    fn write_elf_header(
        bytes: &mut [u8],
        elf_type: u16,
        entry: u64,
        program_count: u16,
        section_offset: u64,
        section_count: u16,
        section_name_index: u16,
    ) {
        bytes[..16].copy_from_slice(b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0");
        write_u16_at(bytes, 16, elf_type);
        write_u16_at(bytes, 18, EM_AARCH64);
        write_u32_at(bytes, 20, 1);
        write_u64_at(bytes, 24, entry);
        write_u64_at(bytes, 32, ELF_HEADER_SIZE as u64);
        write_u64_at(bytes, 40, section_offset);
        write_u32_at(bytes, 48, 0);
        write_u16_at(bytes, 52, ELF_HEADER_SIZE as u16);
        write_u16_at(bytes, 54, PROGRAM_HEADER_SIZE as u16);
        write_u16_at(bytes, 56, program_count);
        write_u16_at(bytes, 58, SECTION_HEADER_SIZE as u16);
        write_u16_at(bytes, 60, section_count);
        write_u16_at(bytes, 62, section_name_index);
    }

    #[allow(clippy::too_many_arguments)]
    fn write_program_header(
        bytes: &mut [u8],
        index: usize,
        program_type: u32,
        flags: u32,
        offset: u64,
        virtual_address: u64,
        file_size: u64,
        memory_size: u64,
        alignment: u64,
    ) {
        let base = ELF_HEADER_SIZE + index * PROGRAM_HEADER_SIZE;
        write_u32_at(bytes, base, program_type);
        write_u32_at(bytes, base + 4, flags);
        write_u64_at(bytes, base + 8, offset);
        write_u64_at(bytes, base + 16, virtual_address);
        write_u64_at(bytes, base + 24, virtual_address);
        write_u64_at(bytes, base + 32, file_size);
        write_u64_at(bytes, base + 40, memory_size);
        write_u64_at(bytes, base + 48, alignment);
    }

    #[allow(clippy::too_many_arguments)]
    fn write_section_header(
        bytes: &mut [u8],
        table_offset: usize,
        index: usize,
        name: u32,
        section_type: u32,
        flags: u64,
        address: u64,
        offset: u64,
        size: u64,
        link: u32,
        info: u32,
        alignment: u64,
        entry_size: u64,
    ) {
        let base = table_offset + index * SECTION_HEADER_SIZE;
        write_u32_at(bytes, base, name);
        write_u32_at(bytes, base + 4, section_type);
        write_u64_at(bytes, base + 8, flags);
        write_u64_at(bytes, base + 16, address);
        write_u64_at(bytes, base + 24, offset);
        write_u64_at(bytes, base + 32, size);
        write_u32_at(bytes, base + 40, link);
        write_u32_at(bytes, base + 44, info);
        write_u64_at(bytes, base + 48, alignment);
        write_u64_at(bytes, base + 56, entry_size);
    }

    #[allow(clippy::too_many_arguments)]
    fn write_symbol(
        bytes: &mut [u8],
        offset: usize,
        name: u32,
        binding: u8,
        symbol_type: u8,
        visibility: u8,
        section_index: u16,
        value: u64,
        size: u64,
    ) {
        write_u32_at(bytes, offset, name);
        bytes[offset + 4] = binding << 4 | symbol_type;
        bytes[offset + 5] = visibility;
        write_u16_at(bytes, offset + 6, section_index);
        write_u64_at(bytes, offset + 8, value);
        write_u64_at(bytes, offset + 16, size);
    }

    fn aarch64_entry_bytes(entry: u64, core: u64, start: u64) -> Vec<u8> {
        [
            0xa9bf_7bfd,
            0xa9bf_07e0,
            0xa9bf_0fe2,
            encode_branch(0x9400_0000, entry + 12, core),
            0xa8c1_0fe2,
            0xa8c1_07e0,
            0xa8c1_7bfd,
            encode_branch(0x1400_0000, entry + 28, start),
        ]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect()
    }

    fn encode_branch(opcode: u32, program_counter: u64, target: u64) -> u32 {
        let displacement = i128::from(target) - i128::from(program_counter);
        assert_eq!(displacement % 4, 0);
        let immediate = displacement / 4;
        assert!((-(1_i128 << 25)..(1_i128 << 25)).contains(&immediate));
        opcode | (immediate as u32 & 0x03ff_ffff)
    }

    fn string_offset(table: &[u8], value: &str) -> u32 {
        let needle = value.as_bytes();
        let offset = table
            .windows(needle.len() + 1)
            .position(|window| window[..needle.len()] == *needle && window[needle.len()] == 0)
            .expect("string is present");
        u32::try_from(offset).expect("fixture string offset")
    }

    fn write_u16_at(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32_at(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64_at(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}
