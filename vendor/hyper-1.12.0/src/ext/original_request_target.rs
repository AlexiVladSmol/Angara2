//! Original HTTP/1 request-target preservation.
//!
//! Hyper normally parses the request-target into `http::Uri`, which discards
//! the fragment and normalizes an empty path to `/`. This extension preserves
//! the exact wire request-target for applications that need to enforce their
//! own URI-form rules. It is inserted for every HTTP/1 server request and does
//! not change parsing or framing.

use bytes::Bytes;

/// The exact HTTP/1 request-target bytes received from the client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginalRequestTarget(Bytes);

impl OriginalRequestTarget {
    pub(crate) fn new(bytes: Bytes) -> Self {
        Self(bytes)
    }

    /// Returns the request-target as a UTF-8 string.
    pub fn as_str(&self) -> &str {
        // Request-target bytes accepted by httparse are visible ASCII.
        std::str::from_utf8(&self.0).expect("HTTP request-target is visible ASCII")
    }

    /// Returns the raw request-target bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<str> for OriginalRequestTarget {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
