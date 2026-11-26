//! Bounded in-memory HTTP cache for the M10 policy.
//!
//! The store keeps only complete `200` responses to ordinary `GET` requests.
//! Access checks, DNS/IP policy and route selection happen before any lookup.
//! Accounting covers body data, keys, stored headers and a fixed entry
//! overhead; allocator bookkeeping and the fixed index structures are
//! additional process overhead and are described in the documentation.

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::convert::Infallible;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use bytes::{Bytes, BytesMut};
use http::header::{
    ACCEPT_ENCODING, AGE, AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_RANGE, COOKIE,
    DATE, ETAG, EXPIRES, IF_MATCH, IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_RANGE, IF_UNMODIFIED_SINCE,
    LAST_MODIFIED, PRAGMA, RANGE, SET_COOKIE, TRAILER, TRANSFER_ENCODING, VARY,
};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode, Version};
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::CacheConfig;
use crate::http::ResponseBody;
use crate::telemetry::Telemetry;

const ENTRY_OVERHEAD: usize = 256;
const HEADER_OVERHEAD: usize = 32;
const KEY_OVERHEAD: usize = 128;
const MAX_URI_EPOCHS: usize = 8_192;

/// Stored representation variant.
///
/// `None` means the response had no Vary field. `AcceptEncoding` distinguishes
/// a `Vary: Accept-Encoding` response with an absent request header from a
/// response without Vary at all, including the empty-header case.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum CacheVariant {
    /// The response had no Vary field.
    None,
    /// The response varied on the request Accept-Encoding value.
    AcceptEncoding(Option<String>),
}

/// One cache lookup key. Raw credentials are never part of the key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct CacheKey {
    uri: String,
    variant: CacheVariant,
    listener_id: String,
    identity: Option<String>,
    egress_id: String,
    endpoints: Vec<SocketAddr>,
    generation: u64,
}

impl CacheKey {
    /// Builds the complete isolation key for one direct request.
    pub(crate) fn new(
        uri: String,
        variant: CacheVariant,
        listener_id: String,
        identity: Option<String>,
        egress_id: String,
        endpoints: Vec<SocketAddr>,
        generation: u64,
    ) -> Self {
        Self {
            uri,
            variant,
            listener_id,
            identity,
            egress_id,
            endpoints,
            generation,
        }
    }

    fn accounted_bytes(&self) -> usize {
        KEY_OVERHEAD
            + self.uri.len()
            + match &self.variant {
                CacheVariant::None => 0,
                CacheVariant::AcceptEncoding(value) => value.as_ref().map_or(0, String::len) + 4,
            }
            + self.listener_id.len()
            + self.identity.as_ref().map_or(0, String::len)
            + self.egress_id.len()
            + self.endpoints.len() * std::mem::size_of::<SocketAddr>()
    }

    fn same_scope(&self, other: &Self) -> bool {
        self.uri == other.uri
            && self.listener_id == other.listener_id
            && self.identity == other.identity
            && self.egress_id == other.egress_id
            && self.endpoints == other.endpoints
            && self.generation == other.generation
    }

    fn variant_conflict(&self, other: &Self) -> bool {
        matches!(
            (&self.variant, &other.variant),
            (CacheVariant::None, CacheVariant::AcceptEncoding(_))
                | (CacheVariant::AcceptEncoding(_), CacheVariant::None)
        )
    }
}

/// Result of one cache lookup.
pub(crate) enum Lookup {
    /// The stored response is still fresh.
    Fresh(Arc<CacheEntry>),
    /// The stored response exists but its freshness lifetime elapsed.
    Stale(Arc<CacheEntry>),
    /// No entry exists for this exact key.
    Miss,
}

/// Request cache directives after conservative parsing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RequestCachePolicy {
    /// Whether the stored response may be read.
    pub(crate) read: bool,
    /// Whether a response to this request may be stored.
    pub(crate) write: bool,
    /// RFC 9111 `only-if-cached`.
    pub(crate) only_if_cached: bool,
    /// RFC 9111 `max-age` constraint.
    pub(crate) max_age: Option<Duration>,
    /// RFC 9111 `min-fresh` constraint.
    pub(crate) min_fresh: Option<Duration>,
}

impl Default for RequestCachePolicy {
    fn default() -> Self {
        Self {
            read: true,
            write: true,
            only_if_cached: false,
            max_age: None,
            min_fresh: None,
        }
    }
}

impl RequestCachePolicy {
    /// Whether the entry age satisfies the client constraints.
    pub(crate) fn accepts_age(&self, age: Duration) -> bool {
        !self.max_age.is_some_and(|max_age| age > max_age)
    }
}

/// Response metadata required to publish one cache entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StorePolicy {
    freshness_lifetime: Duration,
    initial_age: Duration,
}

/// Parses request Cache-Control and client constraints conservatively.
///
/// Unknown or malformed directives are not interpreted as cache permissions:
/// the request is forwarded upstream without reading the cache.
pub(crate) fn analyze_request(headers: &HeaderMap) -> Option<RequestCachePolicy> {
    if headers.contains_key(AUTHORIZATION) || headers.contains_key(COOKIE) {
        return Some(RequestCachePolicy {
            read: false,
            write: false,
            ..RequestCachePolicy::default()
        });
    }
    if headers.contains_key(RANGE)
        || headers.contains_key(IF_RANGE)
        || headers.contains_key(IF_MATCH)
        || headers.contains_key(IF_NONE_MATCH)
        || headers.contains_key(IF_MODIFIED_SINCE)
        || headers.contains_key(IF_UNMODIFIED_SINCE)
    {
        return Some(RequestCachePolicy {
            read: false,
            write: false,
            ..RequestCachePolicy::default()
        });
    }

    let mut policy = RequestCachePolicy::default();
    let directives = match cache_control(headers) {
        Ok(directives) => directives,
        Err(()) => {
            policy.read = false;
            policy.write = false;
            return Some(policy);
        }
    };
    for (name, value) in &directives {
        match name.as_str() {
            "no-store" => {
                policy.read = false;
                policy.write = false;
            }
            "no-cache" => policy.read = false,
            "max-age" => match parse_directive_seconds(value) {
                Ok(Some(seconds)) => {
                    policy.max_age = Some(seconds);
                    if seconds.is_zero() {
                        policy.read = false;
                    }
                }
                _ => {
                    policy.read = false;
                    policy.write = false;
                }
            },
            "min-fresh" => match parse_directive_seconds(value) {
                Ok(Some(seconds)) => policy.min_fresh = Some(seconds),
                _ => {
                    policy.read = false;
                    policy.write = false;
                }
            },
            "only-if-cached" => policy.only_if_cached = true,
            // Other request directives do not grant permissions in M10.
            _ => {}
        }
    }
    if pragma_no_cache(headers) {
        policy.read = false;
    }
    Some(policy)
}

/// Returns the canonical request `Accept-Encoding` value used for the M10
/// variant. `None` (outer) means the header is not usable for caching.
pub(crate) fn request_accept_encoding(headers: &HeaderMap) -> Option<Option<String>> {
    header_value(headers, ACCEPT_ENCODING).ok()
}

/// Parses one Vary response field and the matching request variant.
///
/// M10 supports no Vary and `Vary: Accept-Encoding`. `Vary: *` and every
/// other field combination are excluded from storage.
pub(crate) fn request_variant_for(
    request_headers: &HeaderMap,
    response_headers: &HeaderMap,
) -> Option<CacheVariant> {
    let mut values = Vec::new();
    for value in response_headers.get_all(VARY) {
        let value = value.to_str().ok()?;
        for token in value.split(',') {
            let token = token.trim();
            if token.is_empty() {
                return None;
            }
            values.push(token);
        }
    }
    if values.is_empty() {
        return Some(CacheVariant::None);
    }
    if values
        .iter()
        .all(|token| token.eq_ignore_ascii_case("accept-encoding"))
    {
        return request_accept_encoding(request_headers).map(CacheVariant::AcceptEncoding);
    }
    None
}

/// Computes the freshness metadata for a candidate response.
///
/// Only explicit `s-maxage`, `max-age` or `Expires` values are accepted.
/// Missing, duplicate, malformed or non-positive values are not replaced by a
/// heuristic.
pub(crate) fn analyze_response(
    request_headers: &HeaderMap,
    response_headers: &HeaderMap,
    method: &Method,
    status: StatusCode,
    request_time: SystemTime,
    response_time: SystemTime,
    had_trailers: bool,
) -> Option<StorePolicy> {
    if method != Method::GET || status != StatusCode::OK || had_trailers {
        return None;
    }
    if response_headers.contains_key(SET_COOKIE) || response_headers.contains_key(CONTENT_RANGE) {
        return None;
    }
    // Validators with duplicate values are ambiguous for internal
    // revalidation; do not store such a response.
    let _ = single_header(response_headers, ETAG).ok()?;
    let _ = single_header(response_headers, LAST_MODIFIED).ok()?;
    let directives = cache_control(response_headers).ok()?;
    for (name, _) in &directives {
        if matches!(name.as_str(), "no-store" | "private" | "no-cache") {
            return None;
        }
    }
    let freshness_lifetime = freshness_lifetime(&directives, response_headers, response_time)?;
    let initial_age = initial_age(response_headers, request_time, response_time)?;
    let _variant = request_variant_for(request_headers, response_headers)?;
    Some(StorePolicy {
        freshness_lifetime,
        initial_age,
    })
}

/// Bounded cache store shared by all listeners.
pub(crate) struct CacheStore {
    inner: Mutex<StoreInner>,
    used: Arc<AtomicUsize>,
    max_bytes: usize,
    max_object_bytes: usize,
    max_entries: usize,
    fill_slots: Arc<Semaphore>,
    telemetry: Arc<Telemetry>,
    min_generation: AtomicU64,
    epoch: AtomicU64,
    tick: AtomicU64,
    closed: AtomicBool,
}

struct StoreInner {
    entries: HashMap<CacheKey, Arc<CacheEntry>>,
    // Hashes rather than full URIs keep the bounded registry cheap. A hash
    // collision only cancels an unrelated in-flight fill, which is safe.
    uri_epochs: HashMap<u64, u64>,
}

impl CacheStore {
    /// Creates a store for an enabled cache configuration.
    pub(crate) fn new(config: &CacheConfig, telemetry: Arc<Telemetry>) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(StoreInner {
                entries: HashMap::new(),
                uri_epochs: HashMap::new(),
            }),
            used: Arc::new(AtomicUsize::new(0)),
            max_bytes: config.max_bytes(),
            max_object_bytes: config.max_object_bytes(),
            max_entries: config.max_entries(),
            fill_slots: Arc::new(Semaphore::new(config.max_fills())),
            telemetry,
            min_generation: AtomicU64::new(1),
            epoch: AtomicU64::new(0),
            tick: AtomicU64::new(1),
            closed: AtomicBool::new(false),
        })
    }

    /// Looks up an exact key and returns its freshness state.
    pub(crate) fn lookup(&self, key: &CacheKey, now: SystemTime) -> Lookup {
        let entry = {
            let Ok(inner) = self.inner.lock() else {
                return Lookup::Miss;
            };
            let Some(entry) = inner.entries.get(key).cloned() else {
                return Lookup::Miss;
            };
            let tick = self.tick.fetch_add(1, Ordering::Relaxed);
            entry.last_access.store(tick, Ordering::Relaxed);
            entry
        };
        if entry.is_fresh(now) {
            Lookup::Fresh(entry)
        } else {
            Lookup::Stale(entry)
        }
    }

    /// Removes one exact key after an unusable revalidation.
    pub(crate) fn remove(&self, key: &CacheKey) {
        let removed = {
            let Ok(mut inner) = self.inner.lock() else {
                return;
            };
            self.bump_uri_epoch(&mut inner, &key.uri);
            inner.entries.remove(key)
        };
        drop(removed);
        self.refresh_entries();
    }

    /// Starts a bounded fill, reserving keys and headers immediately.
    pub(crate) fn begin_fill(
        self: &Arc<Self>,
        key: CacheKey,
        headers: HeaderMap,
        policy: StorePolicy,
        expected_len: Option<u64>,
        request_time: SystemTime,
        response_time: SystemTime,
    ) -> Option<CacheFill> {
        let Ok(slot) = self.fill_slots.clone().try_acquire_owned() else {
            self.telemetry
                .cache_fill_refusals
                .fetch_add(1, Ordering::Relaxed);
            return None;
        };
        if self.closed.load(Ordering::Acquire) {
            self.telemetry
                .cache_fill_refusals
                .fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let (epoch, uri_epoch) = self
            .inner
            .lock()
            .map(|inner| {
                (
                    self.epoch.load(Ordering::Acquire),
                    Self::uri_epoch_locked(&inner, &key.uri),
                )
            })
            .unwrap_or((0, 0));
        let mut headers = copy_headers(&headers);
        if crate::http::headers::filter_hop_by_hop(&mut headers, false).is_err() {
            self.telemetry
                .cache_fill_refusals
                .fetch_add(1, Ordering::Relaxed);
            return None;
        }
        headers.remove(AGE);
        if !headers.contains_key(DATE)
            && let Ok(value) = HeaderValue::from_str(&httpdate::fmt_http_date(response_time))
        {
            headers.insert(DATE, value);
        }
        let base_without_body = key
            .accounted_bytes()
            .saturating_add(headers_accounted_bytes(&headers))
            .saturating_add(ENTRY_OVERHEAD);
        if base_without_body > self.max_object_bytes {
            self.telemetry
                .cache_fill_refusals
                .fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let max_body_capacity = self.max_object_bytes.saturating_sub(base_without_body);
        let initial_capacity = match expected_len {
            Some(length) => {
                let Ok(length) = usize::try_from(length) else {
                    self.telemetry
                        .cache_fill_refusals
                        .fetch_add(1, Ordering::Relaxed);
                    return None;
                };
                if length > max_body_capacity {
                    self.telemetry
                        .cache_fill_refusals
                        .fetch_add(1, Ordering::Relaxed);
                    return None;
                }
                length
            }
            None => 0,
        };
        let body = BytesMut::with_capacity(initial_capacity);
        if body.capacity() > max_body_capacity {
            self.telemetry
                .cache_fill_refusals
                .fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let base = base_without_body.saturating_add(body.capacity());
        let Some(account) = self.reserve(base) else {
            self.telemetry
                .cache_fill_refusals
                .fetch_add(1, Ordering::Relaxed);
            return None;
        };
        Some(CacheFill {
            store: Arc::clone(self),
            key,
            headers,
            policy,
            expected_len,
            request_time,
            response_time,
            body,
            data_bytes: 0,
            account,
            _slot: slot,
            epoch,
            uri_epoch,
            max_object_bytes: self.max_object_bytes,
            failed: false,
            finished: false,
        })
    }

    /// Revalidates an existing entry with the headers from a 304 response.
    pub(crate) fn revalidate(
        &self,
        key: &CacheKey,
        entry: &Arc<CacheEntry>,
        headers: &HeaderMap,
        now: SystemTime,
    ) -> bool {
        let Some(meta) = entry.updated_meta(headers, now, &key.variant) else {
            self.remove(key);
            return false;
        };
        let old_header_bytes = entry
            .meta
            .lock()
            .map(|current| headers_accounted_bytes(&current.headers))
            .unwrap_or(0);
        let new_header_bytes = headers_accounted_bytes(&meta.headers);
        if new_header_bytes > old_header_bytes {
            let Ok(mut account) = entry._account.lock() else {
                return false;
            };
            if !self.grow_account(&mut account, new_header_bytes - old_header_bytes) {
                drop(account);
                self.remove(key);
                return false;
            }
        } else if old_header_bytes > new_header_bytes
            && let Ok(mut account) = entry._account.lock()
        {
            account.shrink(old_header_bytes - new_header_bytes);
        }
        let Ok(mut current) = entry.meta.lock() else {
            return false;
        };
        *current = meta;
        true
    }

    /// Invalidates one canonical URI in every variant and scope.
    pub(crate) fn invalidate(&self, uri: &str) {
        let removed = {
            let Ok(mut inner) = self.inner.lock() else {
                return;
            };
            self.bump_uri_epoch(&mut inner, uri);
            let keys = inner
                .entries
                .keys()
                .filter(|key| key.uri == uri)
                .cloned()
                .collect::<Vec<_>>();
            let mut removed = Vec::with_capacity(keys.len());
            for key in keys {
                if let Some(entry) = inner.entries.remove(&key) {
                    removed.push(entry);
                }
            }
            removed
        };
        drop(removed);
        self.refresh_entries();
    }

    /// Drops entries from configuration generations older than `generation`.
    pub(crate) fn retire_before(&self, generation: u64) {
        self.min_generation.fetch_max(generation, Ordering::AcqRel);
        let removed = {
            let Ok(mut inner) = self.inner.lock() else {
                return;
            };
            let keys = inner
                .entries
                .keys()
                .filter(|key| key.generation < generation)
                .cloned()
                .collect::<Vec<_>>();
            let mut removed = Vec::with_capacity(keys.len());
            for key in keys {
                if let Some(entry) = inner.entries.remove(&key) {
                    removed.push(entry);
                }
            }
            removed
        };
        drop(removed);
        self.refresh_entries();
    }

    /// Clears every published entry and invalidates in-flight fills.
    pub(crate) fn clear(&self) {
        self.closed.store(true, Ordering::Release);
        let removed = {
            let Ok(mut inner) = self.inner.lock() else {
                return;
            };
            self.epoch.fetch_add(1, Ordering::AcqRel);
            inner.uri_epochs.clear();
            inner
                .entries
                .drain()
                .map(|(_, entry)| entry)
                .collect::<Vec<_>>()
        };
        drop(removed);
        self.refresh_entries();
    }

    fn refresh_entries(&self) {
        let entries = self
            .inner
            .lock()
            .map(|inner| inner.entries.len())
            .unwrap_or(0);
        self.telemetry.cache_entries.store(
            u64::try_from(entries).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    fn uri_epoch_key(uri: &str) -> u64 {
        let mut hasher = DefaultHasher::new();
        uri.hash(&mut hasher);
        hasher.finish()
    }

    fn uri_epoch_locked(inner: &StoreInner, uri: &str) -> u64 {
        inner
            .uri_epochs
            .get(&Self::uri_epoch_key(uri))
            .copied()
            .unwrap_or(0)
    }

    fn bump_uri_epoch(&self, inner: &mut StoreInner, uri: &str) {
        let key = Self::uri_epoch_key(uri);
        if inner.uri_epochs.len() >= MAX_URI_EPOCHS && !inner.uri_epochs.contains_key(&key) {
            // Keep the per-URI registry bounded. The global bump discards
            // every in-flight fill, which is the conservative fallback when
            // the registry cannot retain another URI.
            self.epoch.fetch_add(1, Ordering::AcqRel);
            inner.uri_epochs.clear();
        }
        let counter = inner.uri_epochs.entry(key).or_insert(0);
        *counter = counter.saturating_add(1);
    }

    fn reserve(&self, bytes: usize) -> Option<Account> {
        if bytes > self.max_bytes {
            return None;
        }
        if let Some(account) = self.try_reserve(bytes) {
            return Some(account);
        }
        loop {
            if !self.evict_one() {
                return None;
            }
            if let Some(account) = self.try_reserve(bytes) {
                return Some(account);
            }
        }
    }

    fn grow_account(&self, account: &mut Account, extra: usize) -> bool {
        if account.grow(extra, self.max_bytes) {
            return true;
        }
        loop {
            if !self.evict_one() {
                return false;
            }
            if account.grow(extra, self.max_bytes) {
                return true;
            }
        }
    }

    fn evict_one(&self) -> bool {
        let victim = {
            let Ok(mut inner) = self.inner.lock() else {
                return false;
            };
            let key = inner
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_access.load(Ordering::Relaxed))
                .map(|(key, _)| key.clone());
            key.and_then(|key| inner.entries.remove(&key))
        };
        let Some(victim) = victim else {
            return false;
        };
        self.telemetry
            .cache_eviction
            .fetch_add(1, Ordering::Relaxed);
        drop(victim);
        self.refresh_entries();
        true
    }

    fn try_reserve(&self, bytes: usize) -> Option<Account> {
        let mut current = self.used.load(Ordering::Acquire);
        loop {
            let next = current.checked_add(bytes)?;
            if next > self.max_bytes {
                return None;
            }
            match self.used.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.telemetry
                        .cache_bytes
                        .store(u64::try_from(next).unwrap_or(u64::MAX), Ordering::Relaxed);
                    return Some(Account {
                        used: Arc::clone(&self.used),
                        telemetry: Arc::clone(&self.telemetry),
                        bytes,
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }

    fn publish(
        &self,
        key: CacheKey,
        entry: Arc<CacheEntry>,
        expected_epoch: u64,
        expected_uri_epoch: u64,
    ) -> bool {
        let (removed, evicted) = {
            let Ok(mut inner) = self.inner.lock() else {
                return false;
            };
            if self.closed.load(Ordering::Acquire)
                || self.epoch.load(Ordering::Acquire) != expected_epoch
                || Self::uri_epoch_locked(&inner, &key.uri) != expected_uri_epoch
                || key.generation < self.min_generation.load(Ordering::Acquire)
            {
                return false;
            }
            entry
                .last_access
                .store(self.tick.fetch_add(1, Ordering::Relaxed), Ordering::Relaxed);
            let mut removed = Vec::new();
            let mut evicted = 0_u64;
            let conflicting = inner
                .entries
                .keys()
                .filter(|candidate| {
                    **candidate != key
                        && key.same_scope(candidate)
                        && key.variant_conflict(candidate)
                })
                .cloned()
                .collect::<Vec<_>>();
            for candidate in conflicting {
                if let Some(entry) = inner.entries.remove(&candidate) {
                    removed.push(entry);
                    evicted = evicted.saturating_add(1);
                }
            }
            if evicted > 0 {
                // A Vary-rule change makes other in-flight fills for this URI
                // incompatible with the newly stored variant.
                self.bump_uri_epoch(&mut inner, &key.uri);
            }
            while inner.entries.len() >= self.max_entries && !inner.entries.contains_key(&key) {
                let Some(victim) = inner
                    .entries
                    .iter()
                    .min_by_key(|(_, candidate)| candidate.last_access.load(Ordering::Relaxed))
                    .map(|(candidate, _)| candidate.clone())
                else {
                    break;
                };
                if let Some(entry) = inner.entries.remove(&victim) {
                    removed.push(entry);
                    evicted = evicted.saturating_add(1);
                }
            }
            if let Some(previous) = inner.entries.insert(key, Arc::clone(&entry)) {
                removed.push(previous);
            }
            (removed, evicted)
        };
        self.telemetry
            .cache_eviction
            .fetch_add(evicted, Ordering::Relaxed);
        drop(removed);
        self.refresh_entries();
        true
    }
}

/// Shared byte-account handle. The counter is released when the last reader
/// drops a body retained after eviction.
struct Account {
    used: Arc<AtomicUsize>,
    telemetry: Arc<Telemetry>,
    bytes: usize,
}

impl Account {
    fn grow(&mut self, extra: usize, max_bytes: usize) -> bool {
        let mut current = self.used.load(Ordering::Acquire);
        loop {
            let Some(next) = current.checked_add(extra) else {
                return false;
            };
            if next > max_bytes {
                return false;
            }
            match self.used.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.bytes = self.bytes.saturating_add(extra);
                    self.telemetry
                        .cache_bytes
                        .store(u64::try_from(next).unwrap_or(u64::MAX), Ordering::Relaxed);
                    return true;
                }
                Err(observed) => current = observed,
            }
        }
    }

    fn shrink(&mut self, bytes: usize) {
        let bytes = bytes.min(self.bytes);
        if bytes == 0 {
            return;
        }
        self.bytes -= bytes;
        let previous = self.used.fetch_sub(bytes, Ordering::AcqRel);
        self.telemetry.cache_bytes.store(
            u64::try_from(previous.saturating_sub(bytes)).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }
}

impl Drop for Account {
    fn drop(&mut self) {
        let previous = self.used.fetch_sub(self.bytes, Ordering::AcqRel);
        self.telemetry.cache_bytes.store(
            u64::try_from(previous.saturating_sub(self.bytes)).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }
}

/// One in-progress response fill.
pub(crate) struct CacheFill {
    store: Arc<CacheStore>,
    key: CacheKey,
    headers: HeaderMap,
    policy: StorePolicy,
    expected_len: Option<u64>,
    request_time: SystemTime,
    response_time: SystemTime,
    body: BytesMut,
    data_bytes: usize,
    account: Account,
    _slot: OwnedSemaphorePermit,
    epoch: u64,
    uri_epoch: u64,
    max_object_bytes: usize,
    failed: bool,
    finished: bool,
}

impl CacheFill {
    /// Copies one body chunk into the fill when limits permit it.
    pub(crate) fn push(&mut self, data: &Bytes) {
        if self.failed || self.finished || data.is_empty() {
            return;
        }
        let Some(new_len) = self.data_bytes.checked_add(data.len()) else {
            self.failed = true;
            return;
        };
        if new_len > self.body.capacity() {
            let base_bytes = self.account.bytes.saturating_sub(self.body.capacity());
            let max_capacity = self.max_object_bytes.saturating_sub(base_bytes);
            if new_len > max_capacity {
                self.failed = true;
                self.store
                    .telemetry
                    .cache_fill_refusals
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
            let mut target = self.body.capacity().max(4096);
            while target < new_len {
                target = target.saturating_mul(2);
            }
            target = target.min(max_capacity);
            let delta = target.saturating_sub(self.body.capacity());
            if delta > 0 && !self.store.grow_account(&mut self.account, delta) {
                self.failed = true;
                self.store
                    .telemetry
                    .cache_fill_refusals
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
            let old_capacity = self.body.capacity();
            self.body.reserve(target.saturating_sub(self.body.len()));
            let actual_delta = self.body.capacity().saturating_sub(old_capacity);
            if actual_delta > delta
                && !self
                    .store
                    .grow_account(&mut self.account, actual_delta - delta)
            {
                self.failed = true;
                self.store
                    .telemetry
                    .cache_fill_refusals
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        self.body.extend_from_slice(data);
        self.data_bytes = new_len;
    }

    /// Publishes the entry only when the complete body was observed.
    pub(crate) fn finish(mut self) -> bool {
        self.finished = true;
        if self.failed {
            return false;
        }
        if let Some(expected) = self.expected_len
            && expected != self.data_bytes as u64
        {
            return false;
        }
        let store = Arc::clone(&self.store);
        let account = self.account;
        let body = std::mem::take(&mut self.body).freeze();
        let entry = Arc::new(CacheEntry {
            body: Arc::new(vec![body]),
            data_bytes: self.data_bytes,
            meta: Mutex::new(EntryMeta {
                headers: std::mem::take(&mut self.headers),
                stored_at: self.response_time,
                initial_age: self.policy.initial_age,
                freshness_lifetime: self.policy.freshness_lifetime,
                request_time: self.request_time,
            }),
            last_access: AtomicU64::new(0),
            _account: Mutex::new(account),
        });
        store.publish(self.key.clone(), entry, self.epoch, self.uri_epoch)
    }
}

/// One published representation.
pub(crate) struct CacheEntry {
    body: Arc<Vec<Bytes>>,
    data_bytes: usize,
    meta: Mutex<EntryMeta>,
    last_access: AtomicU64,
    _account: Mutex<Account>,
}

struct EntryMeta {
    headers: HeaderMap,
    stored_at: SystemTime,
    initial_age: Duration,
    freshness_lifetime: Duration,
    request_time: SystemTime,
}

impl CacheEntry {
    fn is_fresh(&self, now: SystemTime) -> bool {
        let Ok(meta) = self.meta.lock() else {
            return false;
        };
        self.age_from(&meta, now).lt(&meta.freshness_lifetime)
    }

    fn age_from(&self, meta: &EntryMeta, now: SystemTime) -> Duration {
        let resident = now.duration_since(meta.stored_at).unwrap_or(Duration::ZERO);
        meta.initial_age.saturating_add(resident)
    }

    /// Current age of the stored representation.
    pub(crate) fn current_age(&self, now: SystemTime) -> Duration {
        self.meta
            .lock()
            .map(|meta| self.age_from(&meta, now))
            .unwrap_or(Duration::MAX)
    }

    /// Remaining freshness at `now`.
    pub(crate) fn freshness_remaining(&self, now: SystemTime) -> Duration {
        self.meta
            .lock()
            .map(|meta| {
                meta.freshness_lifetime
                    .saturating_sub(self.age_from(&meta, now))
            })
            .unwrap_or(Duration::ZERO)
    }

    /// Stored headers with the current `Age`.
    pub(crate) fn headers(&self) -> HeaderMap {
        let Ok(meta) = self.meta.lock() else {
            return HeaderMap::new();
        };
        let mut headers = meta.headers.clone();
        let age = meta
            .initial_age
            .saturating_add(meta.stored_at.elapsed().unwrap_or(Duration::ZERO));
        headers.remove(AGE);
        if let Ok(value) = HeaderValue::from_str(&age.as_secs().to_string()) {
            headers.insert(AGE, value);
        }
        headers
    }

    /// Validator values copied from the stored representation.
    pub(crate) fn etag(&self) -> Option<HeaderValue> {
        self.meta
            .lock()
            .ok()
            .and_then(|meta| meta.headers.get(ETAG).cloned())
    }

    /// Last-Modified validator copied from the stored representation.
    pub(crate) fn last_modified(&self) -> Option<HeaderValue> {
        self.meta
            .lock()
            .ok()
            .and_then(|meta| meta.headers.get(LAST_MODIFIED).cloned())
    }

    /// Builds the client response for a cache hit.
    pub(crate) fn response(self: &Arc<Self>, instance_id: &str) -> Response<ResponseBody> {
        let mut headers = self.headers();
        headers.remove(TRANSFER_ENCODING);
        headers.remove(TRAILER);
        crate::http::headers::append_via(&mut headers, instance_id);
        if let Ok(value) = HeaderValue::from_str(&self.data_bytes.to_string()) {
            headers.insert(CONTENT_LENGTH, value);
        }
        let body: ResponseBody = CachedBody::new(Arc::clone(self))
            .map_err(|never: Infallible| match never {})
            .boxed();
        let mut response = Response::new(body);
        *response.status_mut() = StatusCode::OK;
        *response.version_mut() = Version::HTTP_11;
        *response.headers_mut() = headers;
        response
    }

    fn updated_meta(
        &self,
        headers: &HeaderMap,
        now: SystemTime,
        old_variant: &CacheVariant,
    ) -> Option<EntryMeta> {
        if headers.contains_key(SET_COOKIE) {
            return None;
        }
        let mut vary_tokens = Vec::new();
        let mut vary_present = false;
        for value in headers.get_all(VARY) {
            vary_present = true;
            let value = value.to_str().ok()?;
            for token in value.split(',') {
                let token = token.trim();
                if token.is_empty() {
                    return None;
                }
                vary_tokens.push(token);
            }
        }
        if vary_present
            && (!vary_tokens
                .iter()
                .all(|token| token.eq_ignore_ascii_case("accept-encoding"))
                || !matches!(old_variant, CacheVariant::AcceptEncoding(_)))
        {
            return None;
        }
        let age_header = single_header(headers, AGE).ok()?;
        let _ = single_header(headers, ETAG).ok()?;
        let _ = single_header(headers, LAST_MODIFIED).ok()?;
        let mut merged = copy_headers(&self.meta.lock().ok()?.headers);
        for name in [CACHE_CONTROL, DATE, ETAG, EXPIRES, LAST_MODIFIED, VARY] {
            replace_header_values(&mut merged, name, headers);
        }
        merged.remove(AGE);
        merged.remove(CONTENT_LENGTH);
        merged.remove(TRANSFER_ENCODING);
        merged.remove(TRAILER);
        if !merged.contains_key(DATE)
            && let Ok(value) = HeaderValue::from_str(&httpdate::fmt_http_date(now))
        {
            merged.insert(DATE, value);
        }
        let directives = cache_control(&merged).ok()?;
        for (name, _) in &directives {
            if matches!(name.as_str(), "no-store" | "private" | "no-cache") {
                return None;
            }
        }
        let freshness_lifetime = freshness_lifetime(&directives, &merged, now)?;
        let initial_age = initial_age_with(headers, age_header, now, now)?;
        let request_time = self
            .meta
            .lock()
            .map(|meta| meta.request_time)
            .unwrap_or(now);
        Some(EntryMeta {
            headers: merged,
            stored_at: now,
            initial_age,
            freshness_lifetime,
            request_time,
        })
    }
}

/// Response body that yields the stored buffer without copying. Holding the
/// `Arc<CacheEntry>` keeps the account alive while a slow reader drains a body
/// that was already evicted from the index.
pub(crate) struct CachedBody {
    entry: Arc<CacheEntry>,
    index: usize,
}

impl CachedBody {
    fn new(entry: Arc<CacheEntry>) -> Self {
        Self { entry, index: 0 }
    }
}

impl Body for CachedBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        let Some(chunk) = self.entry.body.get(self.index).cloned() else {
            return std::task::Poll::Ready(None);
        };
        self.index += 1;
        std::task::Poll::Ready(Some(Ok(Frame::data(chunk))))
    }

    fn is_end_stream(&self) -> bool {
        self.index >= self.entry.body.len()
    }

    fn size_hint(&self) -> SizeHint {
        let remaining = self
            .entry
            .body
            .iter()
            .skip(self.index)
            .map(Bytes::len)
            .sum::<usize>();
        SizeHint::with_exact(remaining as u64)
    }
}

/// Wrapper that fills the cache while the response streams to the client.
pub(crate) struct CacheFillBody {
    inner: ResponseBody,
    fill: Option<CacheFill>,
    done: bool,
}

impl CacheFillBody {
    /// Wraps one response body. Empty bodies are published immediately.
    pub(crate) fn new(inner: ResponseBody, fill: CacheFill) -> Self {
        let mut body = Self {
            inner,
            fill: Some(fill),
            done: false,
        };
        if body.inner.is_end_stream() {
            body.complete();
        }
        body
    }

    fn complete(&mut self) {
        if self.done {
            return;
        }
        self.done = true;
        if let Some(fill) = self.fill.take() {
            let _ = fill.finish();
        }
    }

    fn abort(&mut self) {
        self.done = true;
        self.fill.take();
    }
}

impl Body for CacheFillBody {
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        if self.done {
            return std::task::Poll::Ready(None);
        }
        match std::pin::Pin::new(&mut self.inner).poll_frame(context) {
            std::task::Poll::Ready(Some(Ok(frame))) => {
                let has_trailers = frame.trailers_ref().is_some();
                if let Some(data) = frame.data_ref()
                    && let Some(fill) = self.fill.as_mut()
                {
                    fill.push(data);
                }
                if has_trailers {
                    self.abort();
                } else if self.inner.is_end_stream() {
                    self.complete();
                }
                std::task::Poll::Ready(Some(Ok(frame)))
            }
            std::task::Poll::Ready(Some(Err(error))) => {
                self.abort();
                std::task::Poll::Ready(Some(Err(error)))
            }
            std::task::Poll::Ready(None) => {
                self.complete();
                std::task::Poll::Ready(None)
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for CacheFillBody {
    fn drop(&mut self) {
        if !self.done {
            self.abort();
        }
    }
}

fn copy_header_value(value: &HeaderValue) -> HeaderValue {
    HeaderValue::from_bytes(value.as_bytes()).expect("validated header value")
}

fn copy_headers(headers: &HeaderMap) -> HeaderMap {
    let mut copied = HeaderMap::with_capacity(headers.len());
    for name in headers.keys() {
        for value in headers.get_all(name) {
            copied.append(name.clone(), copy_header_value(value));
        }
    }
    copied
}

fn replace_header_values(target: &mut HeaderMap, name: HeaderName, source: &HeaderMap) {
    let mut values = Vec::new();
    for value in source.get_all(&name) {
        values.push(copy_header_value(value));
    }
    if values.is_empty() {
        return;
    }
    target.remove(&name);
    for value in values {
        target.append(name.clone(), value);
    }
}

fn headers_accounted_bytes(headers: &HeaderMap) -> usize {
    let mut total = 0_usize;
    for name in headers.keys() {
        for value in headers.get_all(name) {
            total = total
                .saturating_add(name.as_str().len())
                .saturating_add(value.len())
                .saturating_add(HEADER_OVERHEAD);
        }
    }
    total
}

fn single_header(headers: &HeaderMap, name: HeaderName) -> Result<Option<&str>, ()> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    value.to_str().map(Some).map_err(|_| ())
}

fn header_value(headers: &HeaderMap, name: HeaderName) -> Result<Option<String>, ()> {
    let mut output = String::new();
    let mut present = false;
    for value in headers.get_all(name) {
        let value = value.to_str().map_err(|_| ())?;
        if present {
            output.push(',');
        }
        output.push_str(value.trim());
        present = true;
    }
    Ok(present.then_some(output))
}

fn pragma_no_cache(headers: &HeaderMap) -> bool {
    headers.get_all(PRAGMA).iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("no-cache"))
        })
    })
}

fn cache_control(headers: &HeaderMap) -> Result<Vec<(String, Option<String>)>, ()> {
    let mut directives: Vec<(String, Option<String>)> = Vec::new();
    for value in headers.get_all(CACHE_CONTROL) {
        let value = value.to_str().map_err(|_| ())?;
        for item in split_directives(value)? {
            let (name, directive_value) = parse_directive(item)?;
            if let Some((_, existing)) = directives.iter().find(|(candidate, _)| candidate == &name)
            {
                if existing != &directive_value {
                    return Err(());
                }
                continue;
            }
            directives.push((name, directive_value));
        }
    }
    Ok(directives)
}

fn split_directives(value: &str) -> Result<Vec<&str>, ()> {
    let bytes = value.as_bytes();
    let mut output = Vec::new();
    let mut start = 0_usize;
    let mut quoted = false;
    let mut escaped = false;
    for (index, byte) in bytes.iter().enumerate() {
        if quoted {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                quoted = false;
            }
        } else if *byte == b'"' {
            quoted = true;
        } else if *byte == b',' {
            output.push(value[start..index].trim());
            start = index + 1;
        }
    }
    if quoted || escaped {
        return Err(());
    }
    output.push(value[start..].trim());
    Ok(output)
}

fn parse_directive(item: &str) -> Result<(String, Option<String>), ()> {
    if item.is_empty() {
        return Err(());
    }
    let (name, value) = match item.split_once('=') {
        Some((name, value)) => (name.trim(), Some(value.trim())),
        None => (item, None),
    };
    if name.is_empty() || !name.bytes().all(is_token_byte) {
        return Err(());
    }
    let value = value.map(unquote).transpose()?;
    Ok((name.to_ascii_lowercase(), value))
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn unquote(value: &str) -> Result<String, ()> {
    let Some(inner) = value.strip_prefix('"') else {
        return Ok(value.to_owned());
    };
    let Some(inner) = inner.strip_suffix('"') else {
        return Err(());
    };
    let mut output = String::with_capacity(inner.len());
    let mut escaped = false;
    for character in inner.chars() {
        if escaped {
            output.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else {
            output.push(character);
        }
    }
    if escaped {
        return Err(());
    }
    Ok(output)
}

fn parse_directive_seconds(value: &Option<String>) -> Result<Option<Duration>, ()> {
    let Some(value) = value else {
        return Err(());
    };
    let value = value.trim();
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(());
    }
    let seconds = value.parse::<u64>().map_err(|_| ())?;
    Ok(Some(Duration::from_secs(seconds)))
}

fn freshness_lifetime(
    directives: &[(String, Option<String>)],
    headers: &HeaderMap,
    _response_time: SystemTime,
) -> Option<Duration> {
    if let Some((_, value)) = directives.iter().find(|(name, _)| name == "s-maxage") {
        return parse_directive_seconds(value).ok()?;
    }
    if let Some((_, value)) = directives.iter().find(|(name, _)| name == "max-age") {
        return parse_directive_seconds(value).ok()?;
    }
    let expires = single_header(headers, EXPIRES).ok()??;
    // `Expires` is only unambiguous together with an explicit `Date`.
    let date = single_header(headers, DATE).ok()??;
    let expires = httpdate::parse_http_date(expires).ok()?;
    let date = httpdate::parse_http_date(date).ok()?;
    Some(expires.duration_since(date).unwrap_or(Duration::ZERO))
}

fn initial_age(
    headers: &HeaderMap,
    request_time: SystemTime,
    response_time: SystemTime,
) -> Option<Duration> {
    let age = single_header(headers, AGE).ok()?;
    initial_age_with(headers, age, request_time, response_time)
}

fn initial_age_with(
    headers: &HeaderMap,
    age: Option<&str>,
    request_time: SystemTime,
    response_time: SystemTime,
) -> Option<Duration> {
    let age = match age {
        Some(value) => Duration::from_secs(parse_age(value)?),
        None => Duration::ZERO,
    };
    let date = match single_header(headers, DATE).ok()? {
        Some(date) => httpdate::parse_http_date(date).ok()?,
        None => response_time,
    };
    let response_delay = response_time
        .duration_since(request_time)
        .unwrap_or(Duration::ZERO);
    let apparent_age = response_time.duration_since(date).unwrap_or(Duration::ZERO);
    let corrected_age = age.saturating_add(response_delay);
    Some(apparent_age.max(corrected_age))
}

fn parse_age(value: &str) -> Option<u64> {
    let value = value.trim();
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(
                HeaderName::from_bytes(name.as_bytes()).expect("header name"),
                HeaderValue::from_str(value).expect("header value"),
            );
        }
        headers
    }

    fn store(
        max_bytes: usize,
        max_object_bytes: usize,
        max_entries: usize,
        max_fills: usize,
    ) -> Arc<CacheStore> {
        let text = format!(
            "schema_version = 1\n[runtime]\nworker_threads = 1\n[limits]\nmax_connections = 8\nmax_header_bytes = 4096\nheader_read_timeout_ms = 1000\nidle_timeout_ms = 5000\nshutdown_timeout_ms = 1000\n[[listeners]]\nid = \"proxy\"\nbind = \"127.0.0.1:3128\"\ntransport = \"http\"\n[cache]\nenabled = true\nmax_bytes = {max_bytes}\nmax_object_bytes = {max_object_bytes}\nmax_entries = {max_entries}\nmax_fills = {max_fills}\n"
        );
        let config = Config::parse(&text).expect("cache config");
        CacheStore::new(config.cache(), Telemetry::new())
    }

    fn policy(seconds: u64) -> StorePolicy {
        StorePolicy {
            freshness_lifetime: Duration::from_secs(seconds),
            initial_age: Duration::ZERO,
        }
    }

    fn key(uri: &str) -> CacheKey {
        CacheKey::new(
            uri.to_owned(),
            CacheVariant::None,
            "proxy".to_owned(),
            None,
            "system".to_owned(),
            vec!["127.0.0.1:8080".parse().expect("endpoint")],
            1,
        )
    }

    #[test]
    fn cache_control_priority_and_invalid_values() {
        let response = headers(&[("cache-control", "s-maxage=4, max-age=2")]);
        let policy = analyze_response(
            &HeaderMap::new(),
            &response,
            &Method::GET,
            StatusCode::OK,
            SystemTime::now(),
            SystemTime::now(),
            false,
        )
        .expect("store policy");
        assert_eq!(policy.freshness_lifetime, Duration::from_secs(4));

        let invalid = headers(&[("cache-control", "max-age=abc")]);
        assert!(
            analyze_response(
                &HeaderMap::new(),
                &invalid,
                &Method::GET,
                StatusCode::OK,
                SystemTime::now(),
                SystemTime::now(),
                false,
            )
            .is_none()
        );
    }

    #[test]
    fn expires_uses_date_and_rejects_missing_date() {
        let response = headers(&[
            ("date", "Sun, 06 Nov 1994 08:49:37 GMT"),
            ("expires", "Sun, 06 Nov 1994 08:49:47 GMT"),
        ]);
        let policy = analyze_response(
            &HeaderMap::new(),
            &response,
            &Method::GET,
            StatusCode::OK,
            SystemTime::now(),
            SystemTime::now(),
            false,
        )
        .expect("expires policy");
        assert_eq!(policy.freshness_lifetime, Duration::from_secs(10));

        let no_date = headers(&[("expires", "Sun, 06 Nov 1994 08:49:47 GMT")]);
        assert!(
            analyze_response(
                &HeaderMap::new(),
                &no_date,
                &Method::GET,
                StatusCode::OK,
                SystemTime::now(),
                SystemTime::now(),
                false,
            )
            .is_none()
        );
    }

    #[test]
    fn age_and_request_constraints() {
        let response = headers(&[
            ("date", "Sun, 06 Nov 1994 08:49:37 GMT"),
            ("age", "4"),
            ("cache-control", "max-age=10"),
        ]);
        let now = httpdate::parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT").expect("date");
        let policy = analyze_response(
            &HeaderMap::new(),
            &response,
            &Method::GET,
            StatusCode::OK,
            now,
            now,
            false,
        )
        .expect("age policy");
        assert_eq!(policy.initial_age, Duration::from_secs(4));

        let request = headers(&[("cache-control", "max-age=2")]);
        assert!(
            !analyze_request(&request)
                .expect("request")
                .accepts_age(Duration::from_secs(4))
        );
        let request = headers(&[("cache-control", "min-fresh=10")]);
        assert_eq!(
            analyze_request(&request).expect("request").min_fresh,
            Some(Duration::from_secs(10))
        );
    }

    #[test]
    fn vary_accept_encoding_is_a_variant_and_star_is_rejected() {
        let response = headers(&[("vary", "Accept-Encoding")]);
        let gzip = headers(&[("accept-encoding", "gzip")]);
        assert_eq!(
            request_variant_for(&gzip, &response),
            Some(CacheVariant::AcceptEncoding(Some("gzip".to_owned())))
        );
        assert_eq!(
            request_variant_for(&HeaderMap::new(), &response),
            Some(CacheVariant::AcceptEncoding(None))
        );
        assert_eq!(
            request_variant_for(&HeaderMap::new(), &HeaderMap::new()),
            Some(CacheVariant::None)
        );

        let star = headers(&[("vary", "*")]);
        assert_eq!(request_variant_for(&HeaderMap::new(), &star), None);
        let other = headers(&[("vary", "Cookie")]);
        assert_eq!(request_variant_for(&HeaderMap::new(), &other), None);
    }

    #[test]
    fn store_evicts_and_accounts_bodies() {
        let store = store(64 * 1024, 16 * 1024, 8, 2);
        for index in 0..10 {
            let uri = format!("http://example.test/{index}");
            let mut fill = store
                .begin_fill(
                    key(&uri),
                    headers(&[("content-length", "8192")]),
                    policy(60),
                    Some(8192),
                    SystemTime::now(),
                    SystemTime::now(),
                )
                .expect("fill");
            fill.push(&Bytes::from(vec![1_u8; 8192]));
            assert!(fill.finish());
        }
        let telemetry = store.telemetry.snapshot();
        assert!(telemetry.cache_entries > 0);
        assert!(telemetry.cache_bytes <= 64 * 1024);
        assert!(telemetry.cache_eviction > 0);
    }

    #[test]
    fn incomplete_or_oversized_fill_is_not_published() {
        let store = store(64 * 1024, 2048, 4, 1);
        let mut fill = store
            .begin_fill(
                key("http://example.test/short"),
                headers(&[("content-length", "1024")]),
                policy(60),
                Some(1024),
                SystemTime::now(),
                SystemTime::now(),
            )
            .expect("fill");
        fill.push(&Bytes::from(vec![1_u8; 10]));
        assert!(!fill.finish());
        assert!(matches!(
            store.lookup(&key("http://example.test/short"), SystemTime::now()),
            Lookup::Miss
        ));

        let mut fill = store
            .begin_fill(
                key("http://example.test/large"),
                HeaderMap::new(),
                policy(60),
                None,
                SystemTime::now(),
                SystemTime::now(),
            )
            .expect("fill");
        fill.push(&Bytes::from(vec![1_u8; 4096]));
        assert!(!fill.finish());
    }

    fn variant_key(uri: &str, variant: CacheVariant) -> CacheKey {
        let mut key = key(uri);
        key.variant = variant;
        key
    }

    #[test]
    fn invalidation_of_another_uri_keeps_the_inflight_fill() {
        let store = store(64 * 1024, 16 * 1024, 4, 1);
        let first = "http://example.test/first";
        let mut fill = store
            .begin_fill(
                key(first),
                HeaderMap::new(),
                policy(60),
                None,
                SystemTime::now(),
                SystemTime::now(),
            )
            .expect("fill");
        fill.push(&Bytes::from_static(b"first"));
        store.invalidate("http://example.test/other");
        assert!(fill.finish());
        assert!(matches!(
            store.lookup(&key(first), SystemTime::now()),
            Lookup::Fresh(_)
        ));
    }

    #[test]
    fn revalidation_updates_header_accounting() {
        let store = store(64 * 1024, 16 * 1024, 4, 1);
        let uri = "http://example.test/revalidate-account";
        let mut fill = store
            .begin_fill(
                key(uri),
                HeaderMap::new(),
                policy(60),
                None,
                SystemTime::now(),
                SystemTime::now(),
            )
            .expect("fill");
        fill.push(&Bytes::from_static(b"body"));
        assert!(fill.finish());
        let entry = match store.lookup(&key(uri), SystemTime::now()) {
            Lookup::Fresh(entry) => entry,
            _ => panic!("entry missing"),
        };
        let before = store.telemetry.cache_bytes.load(Ordering::Relaxed);
        let updated = headers(&[
            ("Cache-Control", "max-age=60"),
            ("ETag", "\"a-very-long-validator-value-for-accounting\""),
        ]);
        assert!(store.revalidate(&key(uri), &entry, &updated, SystemTime::now()));
        let after = store.telemetry.cache_bytes.load(Ordering::Relaxed);
        assert!(
            after > before,
            "header accounting did not grow: {before} -> {after}"
        );
    }

    #[test]
    fn vary_change_removes_incompatible_variant() {
        let store = store(64 * 1024, 16 * 1024, 8, 2);
        let uri = "http://example.test/vary-change";
        for variant in [
            CacheVariant::None,
            CacheVariant::AcceptEncoding(Some("gzip".to_owned())),
        ] {
            let mut fill = store
                .begin_fill(
                    variant_key(uri, variant),
                    HeaderMap::new(),
                    policy(60),
                    None,
                    SystemTime::now(),
                    SystemTime::now(),
                )
                .expect("fill");
            fill.push(&Bytes::from_static(b"body"));
            assert!(fill.finish());
        }
        let gzip = variant_key(uri, CacheVariant::AcceptEncoding(Some("gzip".to_owned())));
        assert!(matches!(
            store.lookup(&key(uri), SystemTime::now()),
            Lookup::Miss
        ));
        assert!(matches!(
            store.lookup(&gzip, SystemTime::now()),
            Lookup::Fresh(_)
        ));

        let mut fill = store
            .begin_fill(
                variant_key(uri, CacheVariant::None),
                HeaderMap::new(),
                policy(60),
                None,
                SystemTime::now(),
                SystemTime::now(),
            )
            .expect("fill");
        fill.push(&Bytes::from_static(b"body"));
        assert!(fill.finish());
        assert!(matches!(
            store.lookup(&gzip, SystemTime::now()),
            Lookup::Miss
        ));
        assert!(matches!(
            store.lookup(&key(uri), SystemTime::now()),
            Lookup::Fresh(_)
        ));
    }

    #[test]
    fn slow_reader_keeps_evicted_object_accounted() {
        let store = store(64 * 1024, 16 * 1024, 1, 2);
        let mut fill = store
            .begin_fill(
                key("http://example.test/held"),
                HeaderMap::new(),
                policy(60),
                None,
                SystemTime::now(),
                SystemTime::now(),
            )
            .expect("fill");
        fill.push(&Bytes::from(vec![1_u8; 8192]));
        assert!(fill.finish());
        let held = match store.lookup(&key("http://example.test/held"), SystemTime::now()) {
            Lookup::Fresh(entry) => entry,
            _ => panic!("entry missing"),
        };

        let mut fill = store
            .begin_fill(
                key("http://example.test/new"),
                HeaderMap::new(),
                policy(60),
                None,
                SystemTime::now(),
                SystemTime::now(),
            )
            .expect("fill");
        fill.push(&Bytes::from(vec![2_u8; 8192]));
        assert!(fill.finish());
        assert!(matches!(
            store.lookup(&key("http://example.test/held"), SystemTime::now()),
            Lookup::Miss
        ));
        let with_held = store.telemetry.cache_bytes.load(Ordering::Relaxed);
        drop(held);
        let after_drop = store.telemetry.cache_bytes.load(Ordering::Relaxed);
        assert!(
            after_drop < with_held,
            "held body was not accounted: {with_held} -> {after_drop}"
        );
    }

    #[test]
    fn invalidation_discards_an_inflight_fill() {
        let store = store(64 * 1024, 16 * 1024, 4, 1);
        let uri = "http://example.test/race";
        let mut fill = store
            .begin_fill(
                key(uri),
                HeaderMap::new(),
                policy(60),
                None,
                SystemTime::now(),
                SystemTime::now(),
            )
            .expect("fill");
        fill.push(&Bytes::from_static(b"old-body"));
        store.invalidate(uri);
        assert!(!fill.finish());
        assert!(matches!(
            store.lookup(&key(uri), SystemTime::now()),
            Lookup::Miss
        ));
    }

    #[test]
    fn request_directives_are_conservative() {
        let no_store = headers(&[("cache-control", "no-store")]);
        let policy = analyze_request(&no_store).expect("request");
        assert!(!policy.read && !policy.write);

        let no_cache = headers(&[("cache-control", "no-cache")]);
        let policy = analyze_request(&no_cache).expect("request");
        assert!(!policy.read && policy.write);

        let only = headers(&[("cache-control", "only-if-cached, max-age=0")]);
        let policy = analyze_request(&only).expect("request");
        assert!(policy.only_if_cached);
        assert!(!policy.read);

        let ranged = headers(&[("range", "bytes=0-1")]);
        let policy = analyze_request(&ranged).expect("request");
        assert!(!policy.read && !policy.write);
    }

    #[test]
    fn response_private_no_store_and_set_cookie_are_not_stored() {
        for header in ["private", "no-store"] {
            let response = headers(&[("cache-control", header)]);
            assert!(
                analyze_response(
                    &HeaderMap::new(),
                    &response,
                    &Method::GET,
                    StatusCode::OK,
                    SystemTime::now(),
                    SystemTime::now(),
                    false,
                )
                .is_none()
            );
        }
        let response = headers(&[("cache-control", "max-age=60"), ("set-cookie", "sid=1")]);
        assert!(
            analyze_response(
                &HeaderMap::new(),
                &response,
                &Method::GET,
                StatusCode::OK,
                SystemTime::now(),
                SystemTime::now(),
                false,
            )
            .is_none()
        );
    }

    #[test]
    fn invalidation_and_generation_retirement_remove_entries() {
        let store = store(64 * 1024, 1024, 4, 1);
        let mut fill = store
            .begin_fill(
                key("http://example.test/a"),
                HeaderMap::new(),
                policy(60),
                None,
                SystemTime::now(),
                SystemTime::now(),
            )
            .expect("fill");
        fill.push(&Bytes::from_static(b"a"));
        assert!(fill.finish());
        store.invalidate("http://example.test/a");
        assert!(matches!(
            store.lookup(&key("http://example.test/a"), SystemTime::now()),
            Lookup::Miss
        ));

        let mut fill = store
            .begin_fill(
                key("http://example.test/b"),
                HeaderMap::new(),
                policy(60),
                None,
                SystemTime::now(),
                SystemTime::now(),
            )
            .expect("fill");
        fill.push(&Bytes::from_static(b"b"));
        assert!(fill.finish());
        store.retire_before(2);
        assert!(matches!(
            store.lookup(&key("http://example.test/b"), SystemTime::now()),
            Lookup::Miss
        ));
    }
}
