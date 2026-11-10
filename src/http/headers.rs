//! HTTP header/error helpers shared by the server and forwarding path.
//!
//! These helpers intentionally use `Result<_, ()>` internally: callers map a
//! malformed peer message to a fixed, non-echoing HTTP status, and no
//! diagnostic text from a peer value is retained.

#![allow(clippy::result_unit_err)]

use std::convert::Infallible;

use bytes::Bytes;
use http::header::{
    AUTHORIZATION, CONNECTION, CONTENT_LENGTH, EXPECT, HOST, MAX_FORWARDS, PROXY_AUTHENTICATE,
    PROXY_AUTHORIZATION, RETRY_AFTER, TE, TRAILER, TRANSFER_ENCODING, UPGRADE, VIA,
    WWW_AUTHENTICATE,
};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode, Version};
use http_body_util::{BodyExt, Full};

use crate::http::ResponseBody;
use crate::target::{CanonicalTarget, Host};

const KEEP_ALIVE: HeaderName = HeaderName::from_static("keep-alive");
const PROXY_CONNECTION: HeaderName = HeaderName::from_static("proxy-connection");
const PROXY_AUTHENTICATION_INFO: HeaderName = HeaderName::from_static("proxy-authentication-info");

/// Parses all Connection/Proxy-Connection nominations and removes hop-by-hop fields.
pub fn filter_hop_by_hop(headers: &mut HeaderMap, request: bool) -> Result<(), ()> {
    let mut nominated = Vec::new();
    for name in [CONNECTION, PROXY_CONNECTION] {
        for value in headers.get_all(name) {
            let value = value.to_str().map_err(|_| ())?;
            for token in value.split(',') {
                let token = token.trim();
                if token.is_empty() {
                    return Err(());
                }
                nominated.push(HeaderName::from_bytes(token.as_bytes()).map_err(|_| ())?);
            }
        }
    }

    for name in nominated {
        headers.remove(name);
    }
    for name in [
        CONNECTION,
        PROXY_CONNECTION,
        KEEP_ALIVE,
        UPGRADE,
        TE,
        TRAILER,
        TRANSFER_ENCODING,
        CONTENT_LENGTH,
    ] {
        headers.remove(name);
    }
    if request {
        headers.remove(PROXY_AUTHORIZATION);
        headers.remove(PROXY_AUTHENTICATION_INFO);
    } else {
        headers.remove(PROXY_AUTHENTICATE);
        headers.remove(PROXY_AUTHENTICATION_INFO);
    }
    Ok(())
}

/// Validates request/response framing before hyper's normalized body is used.
///
/// M03 accepts exactly one `chunked` transfer coding and never a simultaneous
/// Content-Length. Equal duplicate Content-Length values are unambiguous;
/// conflicting or comma-mixed values are rejected.
pub fn validate_framing(headers: &HeaderMap) -> Result<(), ()> {
    let mut lengths = Vec::new();
    for value in headers.get_all(CONTENT_LENGTH) {
        let value = value.to_str().map_err(|_| ())?;
        for part in value.split(',') {
            let part = part.trim();
            if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(());
            }
            lengths.push(part.parse::<u64>().map_err(|_| ())?);
        }
    }
    if let Some(first) = lengths.first()
        && lengths.iter().any(|length| length != first)
    {
        return Err(());
    }

    let mut chunked = 0_usize;
    for value in headers.get_all(TRANSFER_ENCODING) {
        let value = value.to_str().map_err(|_| ())?;
        for token in value.split(',') {
            let token = token.trim();
            if token.is_empty() || !token.eq_ignore_ascii_case("chunked") {
                return Err(());
            }
            chunked += 1;
        }
    }
    if chunked > 1 {
        return Err(());
    }
    if chunked == 1 && !lengths.is_empty() {
        return Err(());
    }
    Ok(())
}

/// Returns true when a field name is nominated by Connection/Proxy-Connection.
pub fn is_nominated(headers: &HeaderMap, name: &str) -> bool {
    [CONNECTION, PROXY_CONNECTION].iter().any(|header| {
        headers.get_all(header).iter().any(|value| {
            value.to_str().is_ok_and(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case(name))
            })
        })
    })
}

/// Removes fields that must not appear in trailers.
pub fn filter_trailers(headers: &mut HeaderMap) -> Result<(), ()> {
    let mut nominated = Vec::new();
    for value in headers.get_all(CONNECTION) {
        let value = value.to_str().map_err(|_| ())?;
        for token in value.split(',') {
            let token = token.trim();
            if token.is_empty() {
                return Err(());
            }
            nominated.push(HeaderName::from_bytes(token.as_bytes()).map_err(|_| ())?);
        }
    }
    for name in nominated {
        headers.remove(name);
    }
    for name in [
        CONNECTION,
        CONTENT_LENGTH,
        HOST,
        TE,
        TRAILER,
        TRANSFER_ENCODING,
        UPGRADE,
        AUTHORIZATION,
        PROXY_AUTHORIZATION,
        PROXY_AUTHENTICATE,
        PROXY_AUTHENTICATION_INFO,
        VIA,
        MAX_FORWARDS,
    ] {
        headers.remove(name);
    }
    Ok(())
}

/// Adds `Via: 1.1 angara` while preserving previous values.
pub fn append_via(headers: &mut HeaderMap) {
    headers.append(VIA, HeaderValue::from_static("1.1 angara"));
}

/// Detects Angara's own received-by token in the input Via chain.
pub fn via_has_angara(headers: &HeaderMap) -> bool {
    for value in headers.get_all(VIA) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for entry in value.split(',') {
            let mut parts = entry.split_whitespace();
            let _protocol = parts.next();
            if let Some(received_by) = parts.next() {
                let host = received_by.split(':').next().unwrap_or(received_by);
                if host.eq_ignore_ascii_case("angara") {
                    return true;
                }
            }
        }
    }
    false
}

/// Parses a single Max-Forwards value. `None` means absent.
pub fn max_forwards(headers: &HeaderMap) -> Result<Option<u32>, ()> {
    let mut values = headers.get_all(MAX_FORWARDS).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    let value = value.to_str().map_err(|_| ())?.trim();
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(());
    }
    value.parse::<u32>().map(Some).map_err(|_| ())
}

/// Writes a decremented Max-Forwards value.
pub fn set_max_forwards(headers: &mut HeaderMap, value: u32) {
    let value = HeaderValue::from_str(&value.to_string()).expect("decimal header value");
    headers.insert(MAX_FORWARDS, value);
}

/// Validates the single Expect header.
pub fn expect_continue(headers: &HeaderMap) -> Result<bool, ()> {
    let mut values = headers.get_all(EXPECT).iter();
    let Some(value) = values.next() else {
        return Ok(false);
    };
    if values.next().is_some() {
        return Err(());
    }
    let value = value.to_str().map_err(|_| ())?;
    let mut tokens = value.split(',').map(str::trim);
    let Some(token) = tokens.next() else {
        return Err(());
    };
    if tokens.next().is_some() || !token.eq_ignore_ascii_case("100-continue") {
        return Err(());
    }
    Ok(true)
}

/// Removes Expect before forwarding.
pub fn remove_expect(headers: &mut HeaderMap) {
    headers.remove(EXPECT);
}

/// True for an Upgrade request or Upgrade nomination.
pub fn has_upgrade(headers: &HeaderMap) -> bool {
    if headers.contains_key(UPGRADE) {
        return true;
    }
    headers.get_all(CONNECTION).iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        })
    })
}

/// Builds the canonical Host header value for an HTTP target.
pub fn build_host(target: &CanonicalTarget) -> String {
    let host = match target.host() {
        Host::Domain(domain) => domain.to_string(),
        Host::Ip(ip) => match ip {
            std::net::IpAddr::V4(ip) => ip.to_string(),
            std::net::IpAddr::V6(ip) => format!("[{ip}]"),
        },
    };
    if target.port() == 80 {
        host
    } else {
        format!("{host}:{}", target.port())
    }
}

/// Replaces all Host values with exactly the canonical target Host.
pub fn set_canonical_host(headers: &mut HeaderMap, target: &CanonicalTarget) {
    headers.remove(HOST);
    let host = HeaderValue::from_str(&build_host(target)).expect("ASCII Host");
    headers.insert(HOST, host);
}

/// Origin-form path and query for the upstream request.
pub fn origin_form(target: &CanonicalTarget) -> &str {
    target
        .path_and_query()
        .map(|path| path.as_str())
        .unwrap_or("/")
}

/// Returns whether the request method/status forbids a body on the wire.
pub fn response_has_body(method: &Method, status: StatusCode) -> bool {
    method != Method::HEAD
        && status != StatusCode::NO_CONTENT
        && status != StatusCode::NOT_MODIFIED
        && !status.is_informational()
}

/// Parses and sanitizes announced trailer field names.
///
/// Forbidden framing, routing, authentication and control fields are removed;
/// a malformed token list is rejected.
pub fn trailer_names(headers: &HeaderMap) -> Result<Vec<HeaderName>, ()> {
    let mut names = Vec::new();
    for value in headers.get_all(TRAILER) {
        let value = value.to_str().map_err(|_| ())?;
        for token in value.split(',') {
            let token = token.trim();
            if token.is_empty() {
                return Err(());
            }
            let name = HeaderName::from_bytes(token.as_bytes()).map_err(|_| ())?;
            if !is_forbidden_trailer(&name) && !names.contains(&name) {
                names.push(name);
            }
        }
    }
    Ok(names)
}

/// Replaces the `Trailer` header with sanitized names.
pub fn set_trailer_names(headers: &mut HeaderMap, names: &[HeaderName]) {
    headers.remove(TRAILER);
    if names.is_empty() {
        return;
    }
    let value = names
        .iter()
        .map(HeaderName::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    if let Ok(value) = HeaderValue::from_str(&value) {
        headers.insert(TRAILER, value);
    }
}

fn is_forbidden_trailer(name: &HeaderName) -> bool {
    name == CONNECTION
        || name == CONTENT_LENGTH
        || name == HOST
        || name == TE
        || name == TRAILER
        || name == TRANSFER_ENCODING
        || name == UPGRADE
        || name == AUTHORIZATION
        || name == PROXY_AUTHORIZATION
        || name == PROXY_AUTHENTICATE
        || name == PROXY_AUTHENTICATION_INFO
        || name == WWW_AUTHENTICATE
        || name == VIA
        || name == MAX_FORWARDS
        || name == EXPECT
        || name == KEEP_ALIVE
        || name == PROXY_CONNECTION
}

/// Adds `TE: trailers` for the origin hop.
pub fn set_te_trailers(headers: &mut HeaderMap) {
    headers.insert(TE, HeaderValue::from_static("trailers"));
}

/// Whether the incoming message advertised `TE: trailers`.
pub fn accepts_trailers(headers: &HeaderMap) -> bool {
    headers.get_all(TE).iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("trailers"))
        })
    })
}

/// Writes an exact Content-Length header.
pub fn set_content_length(headers: &mut HeaderMap, length: u64) {
    let value = HeaderValue::from_str(&length.to_string()).expect("decimal header value");
    headers.insert(CONTENT_LENGTH, value);
}

/// Copies the representation Content-Length for HEAD/304 responses.
pub fn keep_representation_length(headers: &mut HeaderMap, original: &HeaderMap) {
    headers.remove(CONTENT_LENGTH);
    if let Some(value) = original.get(CONTENT_LENGTH) {
        headers.insert(CONTENT_LENGTH, value.clone());
    }
}

/// Creates a bounded local response with no body.
pub fn error_response(status: StatusCode, close: bool) -> Response<ResponseBody> {
    let mut builder = Response::builder().status(status).version(Version::HTTP_11);
    if close {
        builder = builder.header(CONNECTION, HeaderValue::from_static("close"));
    }
    if status == StatusCode::SERVICE_UNAVAILABLE {
        builder = builder.header(RETRY_AFTER, HeaderValue::from_static("1"));
    }
    let body = Full::new(Bytes::new())
        .map_err(|never: Infallible| match never {})
        .boxed();
    builder.body(body).unwrap_or_else(|_| {
        Response::new(
            Full::new(Bytes::new())
                .map_err(|never: Infallible| match never {})
                .boxed(),
        )
    })
}
