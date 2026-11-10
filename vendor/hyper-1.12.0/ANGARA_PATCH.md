# Angara patch for hyper 1.12.0

Base: crates.io `hyper` **1.12.0** (checksum in `Cargo.lock` history / vendored
source matches the published crate).
Purpose: expose the original HTTP/1 request-target to server services before
hyper converts it to `http::Uri`.

Scope is intentionally limited to request metadata:

- request-target bytes are copied from the already parsed HTTP/1 head;
- they are inserted into `Request::extensions` as
  `hyper::ext::OriginalRequestTarget`;
- parser, `Content-Length`, `Transfer-Encoding`, chunked decoder, body
  handling and keep-alive logic are unchanged.

The Angara crate pins the patched source through `[patch.crates-io]` and the
vendored directory, so a clean clone builds without modifying a local Cargo
cache. Re-check this patch when upgrading hyper.

## Exact diff

```diff
diff --git a/src/ext/mod.rs b/src/ext/mod.rs
--- a/src/ext/mod.rs
+++ b/src/ext/mod.rs
@@ -54,6 +54,11 @@ mod h1_reason_phrase;
 #[cfg(any(feature = "http1", feature = "ffi"))]
 pub use h1_reason_phrase::ReasonPhrase;
 
+#[cfg(all(feature = "http1", feature = "server"))]
+mod original_request_target;
+#[cfg(all(feature = "http1", feature = "server"))]
+pub use original_request_target::OriginalRequestTarget;
+
 #[cfg(all(feature = "http1", feature = "client"))]
 mod informational;
 #[cfg(all(feature = "http1", feature = "client"))]
 pub use informational::on_informational;
```

New file `src/ext/original_request_target.rs`:

```rust
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
```

```diff
diff --git a/src/proto/h1/role.rs b/src/proto/h1/role.rs
--- a/src/proto/h1/role.rs
+++ b/src/proto/h1/role.rs
@@ -18,6 +18,8 @@ use crate::body::DecodedLength;
 use crate::common::date;
 use crate::error::Parse;
 use crate::ext::HeaderCaseMap;
+#[cfg(all(feature = "server", feature = "http1"))]
+use crate::ext::OriginalRequestTarget;
 #[cfg(feature = "ffi")]
 use crate::ext::OriginalHeaderOrder;
 use crate::headers;
@@ -223,8 +225,10 @@ impl Http1Transaction for Server {
         };
 
         let slice = buf.split_to(len).freeze();
+        let target_bytes = slice.slice_ref(&slice[path_range]);
+        let original_target = OriginalRequestTarget::new(target_bytes.clone());
         let uri = {
-            let uri_bytes = slice.slice_ref(&slice[path_range]);
+            let uri_bytes = target_bytes;
             // TODO(lucab): switch to `Uri::from_shared()` once public.
             http::Uri::from_maybe_shared(uri_bytes)?
         };
@@ -362,6 +366,8 @@ impl Http1Transaction for Server {
 
         let mut extensions = http::Extensions::default();
 
+        extensions.insert(original_target);
+
         if let Some(header_case_map) = header_case_map {
             extensions.insert(header_case_map);
         }
```

This is the complete behavioral change. No other hyper files differ from the
published 1.12.0 source.
