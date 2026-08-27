//! OS-owned backend request-identity seam for semantic direct-tool calls.
//!
//! The promoted trusted-context path does not use the ephemeral implementation
//! in this module: its durable operation journal authors the replay identity
//! before any backend effect.  The implementation below keeps the ordinary
//! source/dev compatibility lane free of model-authored IDs by deriving a
//! process-local sequence from kernel randomness.  It is deliberately not a
//! restart-stable or production exactly-once authority.

use sha2::{Digest as _, Sha256};

use crate::{DirectToolError, Result};

const IDENTITY_DOMAIN: &[u8] = b"trillionnium.semantic-backend-request-identity.v1\0";
const RANDOM_BYTES: usize = 32;

/// Injectable boundary between one validated semantic action and its backend
/// replay identity. Implementations must never accept an identity string from
/// the semantic/model request.
pub trait BackendRequestIdentityAuthor {
    fn author_backend_request_id(
        &mut self,
        adapter: &'static str,
        semantic_request: &[u8],
    ) -> Result<String>;
}

/// Source/dev compatibility author.
///
/// A fresh kernel-random epoch plus a checked process-local sequence prevents
/// the model from selecting or colliding request IDs. It does not survive a
/// process restart, so product exactly-once activation still requires the
/// durable trusted-context journal.
pub struct EphemeralOsRequestIdentityAuthor {
    epoch: [u8; RANDOM_BYTES],
    next_sequence: u64,
}

impl EphemeralOsRequestIdentityAuthor {
    pub fn from_kernel() -> Result<Self> {
        let mut epoch = [0_u8; RANDOM_BYTES];
        let mut offset = 0;
        while offset < epoch.len() {
            let result = unsafe {
                libc::getrandom(epoch[offset..].as_mut_ptr().cast(), epoch.len() - offset, 0)
            };
            if result > 0 {
                offset += usize::try_from(result).map_err(|_| {
                    DirectToolError::BackendUnavailable(
                        "kernel randomness returned an invalid byte count".to_string(),
                    )
                })?;
                continue;
            }
            if result < 0
                && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
            {
                continue;
            }
            return Err(DirectToolError::BackendUnavailable(
                "kernel randomness is unavailable for semantic request identity".to_string(),
            ));
        }
        Ok(Self {
            epoch,
            next_sequence: 0,
        })
    }
}

impl BackendRequestIdentityAuthor for EphemeralOsRequestIdentityAuthor {
    fn author_backend_request_id(
        &mut self,
        adapter: &'static str,
        semantic_request: &[u8],
    ) -> Result<String> {
        if adapter.is_empty() || semantic_request.is_empty() {
            return Err(DirectToolError::InvalidRequest(
                "semantic request identity input is empty".to_string(),
            ));
        }
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.checked_add(1).ok_or_else(|| {
            DirectToolError::BackendUnavailable(
                "ephemeral semantic request identity sequence is exhausted".to_string(),
            )
        })?;
        let mut hasher = Sha256::new();
        hasher.update(IDENTITY_DOMAIN);
        hasher.update(adapter.as_bytes());
        hasher.update([0]);
        hasher.update(self.epoch);
        hasher.update(sequence.to_be_bytes());
        hasher.update(Sha256::digest(semantic_request));
        Ok(format!("os:{:x}", hasher.finalize()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_author_is_bounded_distinct_and_not_caller_selected() {
        let mut author = EphemeralOsRequestIdentityAuthor {
            epoch: [7; RANDOM_BYTES],
            next_sequence: 0,
        };
        let first = author
            .author_backend_request_id("system_api", br#"{"action":"launch_package"}"#)
            .unwrap();
        let second = author
            .author_backend_request_id("system_api", br#"{"action":"launch_package"}"#)
            .unwrap();
        assert!(crate::valid_request_id(&first));
        assert!(first.starts_with("os:"));
        assert_eq!(first.len(), 67);
        assert_ne!(first, second);
        assert!(!first.contains("launch_package"));
    }

    #[test]
    fn source_author_fails_closed_at_sequence_exhaustion() {
        let mut author = EphemeralOsRequestIdentityAuthor {
            epoch: [9; RANDOM_BYTES],
            next_sequence: u64::MAX,
        };
        assert!(
            author
                .author_backend_request_id("accessibility", br#"{"action":"snapshot"}"#)
                .is_err()
        );
    }
}
