//! Shared validation for canonical SHA-256 hex encodings.
//!
//! These helpers deliberately distinguish a syntactically valid lowercase
//! digest from an identity/root digest for which the all-zero sentinel is not
//! admissible. Callers must choose the semantic boundary explicitly.

pub const SHA256_HEX_LEN: usize = 64;

/// Returns true for exactly 64 lowercase ASCII hexadecimal characters.
///
/// The all-zero digest is syntactically valid and is accepted here.
pub fn is_lower_sha256(value: &str) -> bool {
    value.len() == SHA256_HEX_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Returns true for a canonical lowercase SHA-256 digest other than all-zero.
pub fn is_nonzero_lower_sha256(value: &str) -> bool {
    is_lower_sha256(value) && value.bytes().any(|byte| byte != b'0')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lowercase_validation_keeps_zero_semantics_explicit() {
        let zero = "0".repeat(SHA256_HEX_LEN);
        let nonzero = format!("{}1", "0".repeat(SHA256_HEX_LEN - 1));
        assert!(is_lower_sha256(&zero));
        assert!(!is_nonzero_lower_sha256(&zero));
        assert!(is_lower_sha256(&nonzero));
        assert!(is_nonzero_lower_sha256(&nonzero));
    }

    #[test]
    fn rejects_noncanonical_or_wrong_length_encodings() {
        for value in [
            "a".repeat(SHA256_HEX_LEN - 1),
            "a".repeat(SHA256_HEX_LEN + 1),
            "A".repeat(SHA256_HEX_LEN),
            "g".repeat(SHA256_HEX_LEN),
            "é".repeat(SHA256_HEX_LEN),
        ] {
            assert!(!is_lower_sha256(&value));
            assert!(!is_nonzero_lower_sha256(&value));
        }
    }
}
