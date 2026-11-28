//! Content versions shared by the control API and file editor.
//!
//! A version is the SHA-256 of the exact bytes read from disk, rendered as
//! lowercase hexadecimal. It is an equality token, not a secret or a signature.

use ring::digest;

/// Prefix used by every published content version.
pub const VERSION_PREFIX: &str = "sha256:";

/// Computes the version token for one file or protocol snapshot.
pub fn content_version(bytes: &[u8]) -> String {
    let digest = digest::digest(&digest::SHA256, bytes);
    let mut value = String::with_capacity(VERSION_PREFIX.len() + digest.as_ref().len() * 2);
    value.push_str(VERSION_PREFIX);
    for byte in digest.as_ref() {
        use std::fmt::Write;
        let _ = write!(value, "{byte:02x}");
    }
    value
}

/// Whether a string is a syntactically valid content version.
pub fn is_version(value: &str) -> bool {
    let Some(hex) = value.strip_prefix(VERSION_PREFIX) else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_stable_and_domain_separated() {
        let empty = content_version(b"");
        let one = content_version(b"a");
        assert_eq!(
            empty,
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_ne!(empty, one);
        assert!(is_version(&empty));
        assert!(!is_version("sha256:00"));
        assert!(!is_version(&empty.to_uppercase()));
    }
}
