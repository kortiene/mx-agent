//! Nonce replay protection and request expiry checks for privileged requests
//! (architecture §11.2, §13).
//!
//! Privileged events such as `com.mxagent.exec.request.v1` and
//! `com.mxagent.call.request.v1` carry a random `nonce` and an `expires_at`
//! timestamp. Before a daemon acts on such a request it must:
//!
//! 1. Reject the request if it has already expired (`expires_at` is at or
//!    before "now"), and
//! 2. Reject the request if its nonce has been seen before (a replay).
//!
//! Crucially, an *expired* request is rejected **without side effects**: its
//! nonce is never recorded, so the cache cannot be grown or evicted by stale or
//! malicious requests, and re-presenting the same expired request never changes
//! the daemon's state.
//!
//! The cache is bounded: it holds at most [`ReplayCache::capacity`] entries.
//! When admitting a new nonce would exceed the bound, already-expired entries
//! are pruned first; if still full, the entry that expires soonest is evicted.
//! The cache is persisted to daemon-owned storage (`0600`) so replay protection
//! survives daemon restarts, and expired entries are pruned on load.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::session::SessionPaths;

/// Default maximum number of nonces retained in the replay cache.
pub const DEFAULT_CAPACITY: usize = 8192;

/// File name of the persisted replay cache inside the data directory.
const REPLAY_CACHE_FILE: &str = "replay_cache.json";

/// Reasons a privileged request can be denied by the replay cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayError {
    /// The request expired at or before the current time. Denied without
    /// recording the nonce, so it has no effect on the cache.
    Expired,
    /// The request's nonce has been seen before (a replay).
    Replayed,
    /// The `expires_at` timestamp was not a valid RFC 3339 instant.
    MalformedTimestamp,
    /// The persisted cache file exists but could not be parsed. The daemon
    /// fails closed (refuses to admit) rather than silently resetting to an
    /// empty cache and forgetting every previously burned nonce; the corrupt
    /// file is quarantined for inspection. Produced only by
    /// [`ReplayCache::load`].
    Corrupt,
    /// Persisting the cache to disk failed.
    Io(io::ErrorKind),
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expired => write!(f, "privileged request has expired"),
            Self::Replayed => write!(f, "privileged request nonce was already used"),
            Self::MalformedTimestamp => write!(f, "expires_at is not a valid RFC 3339 timestamp"),
            Self::Corrupt => write!(f, "replay cache file is corrupt"),
            Self::Io(kind) => write!(f, "replay cache I/O error: {kind:?}"),
        }
    }
}

impl std::error::Error for ReplayError {}

/// On-disk representation of the replay cache.
#[derive(Debug, Default, Serialize, Deserialize)]
struct StoredCache {
    /// Maximum number of entries the cache retains.
    capacity: usize,
    /// Map of seen nonce -> request expiry, as Unix seconds.
    nonces: HashMap<String, i64>,
}

/// A bounded, persistent cache of recently seen request nonces.
#[derive(Debug)]
pub struct ReplayCache {
    path: PathBuf,
    capacity: usize,
    /// Map of nonce -> `expires_at` as Unix seconds.
    nonces: HashMap<String, i64>,
}

impl ReplayCache {
    /// Load the replay cache from daemon-owned storage, creating an empty cache
    /// (with [`DEFAULT_CAPACITY`]) on first run. Expired entries are pruned on
    /// load so a restart does not resurrect stale nonces.
    pub fn load(paths: &SessionPaths) -> Result<Self, ReplayError> {
        Self::load_with_capacity(paths, DEFAULT_CAPACITY)
    }

    /// Like [`load`](Self::load) but with an explicit `capacity` used when no
    /// cache exists yet. A capacity of zero is treated as one entry.
    pub fn load_with_capacity(paths: &SessionPaths, capacity: usize) -> Result<Self, ReplayError> {
        let path = paths.data_dir.join(REPLAY_CACHE_FILE);

        // A prior corrupt load moved the cache aside to a sibling
        // `replay_cache.json.corrupt` and failed closed. Keep failing closed
        // while that sentinel exists: otherwise this load would find the
        // original path absent (the `NotFound` branch below), silently return a
        // fresh empty cache, and forget every previously burned nonce — exactly
        // the silent reset the quarantine exists to prevent (and which sibling
        // agents later in the same scheduler pass would also inherit). The
        // daemon stays fail-closed until an operator clears the quarantined
        // file.
        let quarantine = quarantine_path(&path);
        if quarantine.exists() {
            tracing::error!(
                path = %quarantine.display(),
                "quarantined corrupt replay cache present; refusing to admit (fail closed). \
                 Move the quarantined file aside to reset replay protection."
            );
            return Err(ReplayError::Corrupt);
        }

        let now = now_unix();
        let mut cache = match fs::read(&path) {
            Ok(bytes) => {
                let stored: StoredCache = match serde_json::from_slice(&bytes) {
                    Ok(stored) => stored,
                    Err(_) => {
                        // Do NOT silently reset to an empty cache: that would
                        // forget every previously burned nonce with no
                        // operator-visible signal, weakening replay protection
                        // for every caller (the otherwise fail-closed sync
                        // router included). Quarantine the corrupt bytes for
                        // inspection — rather than overwriting them on the next
                        // persist — and fail closed; callers (router, scheduler)
                        // then skip routing/dispatch until an operator moves the
                        // quarantined file aside.
                        quarantine_corrupt(&path);
                        tracing::error!(
                            path = %path.display(),
                            "replay cache file is corrupt; refusing to admit (fail closed). \
                             Move the quarantined file aside to reset replay protection."
                        );
                        return Err(ReplayError::Corrupt);
                    }
                };
                Self {
                    path,
                    capacity: stored.capacity.max(1),
                    nonces: stored.nonces,
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Self {
                path,
                capacity: capacity.max(1),
                nonces: HashMap::new(),
            },
            Err(e) => return Err(ReplayError::Io(e.kind())),
        };
        cache.prune_expired(now);
        Ok(cache)
    }

    /// The configured maximum number of retained nonces.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// The current number of retained nonces.
    pub fn len(&self) -> usize {
        self.nonces.len()
    }

    /// Whether the cache currently holds no nonces.
    pub fn is_empty(&self) -> bool {
        self.nonces.is_empty()
    }

    /// Admit a privileged request, checking expiry and replay against the
    /// current wall-clock time.
    ///
    /// On success the nonce is recorded and the cache is persisted. See
    /// [`admit_at`](Self::admit_at) for the precise semantics.
    pub fn admit(&mut self, nonce: &str, expires_at: &str) -> Result<(), ReplayError> {
        self.admit_at(nonce, expires_at, now_unix())
    }

    /// Admit a privileged request relative to an explicit `now` (Unix seconds).
    ///
    /// Returns:
    /// - [`ReplayError::MalformedTimestamp`] if `expires_at` cannot be parsed,
    /// - [`ReplayError::Expired`] if the request expired at or before `now`,
    /// - [`ReplayError::Replayed`] if `nonce` has been admitted before.
    ///
    /// All denials are side-effect free: the cache is neither mutated nor
    /// persisted, so an expired or replayed request can never evict valid
    /// entries or grow the cache. On success the nonce is recorded (evicting
    /// expired or soonest-to-expire entries to honor the capacity bound) and
    /// the cache is persisted atomically.
    pub fn admit_at(&mut self, nonce: &str, expires_at: &str, now: i64) -> Result<(), ReplayError> {
        let expiry = parse_rfc3339_to_unix(expires_at).ok_or(ReplayError::MalformedTimestamp)?;

        // Expired requests are rejected without side effects.
        if expiry <= now {
            return Err(ReplayError::Expired);
        }

        // Replays are rejected without side effects.
        if self.nonces.contains_key(nonce) {
            return Err(ReplayError::Replayed);
        }

        // Record the nonce, honoring the capacity bound.
        self.prune_expired(now);
        while self.nonces.len() >= self.capacity {
            // Evict the entry that expires soonest; it is the least useful to
            // keep for replay protection.
            if let Some(victim) = self
                .nonces
                .iter()
                .min_by_key(|(_, &exp)| exp)
                .map(|(k, _)| k.clone())
            {
                self.nonces.remove(&victim);
            } else {
                break;
            }
        }
        self.nonces.insert(nonce.to_string(), expiry);
        self.persist()
    }

    /// Remove a previously admitted nonce, persisting the change. A no-op (still
    /// `Ok`) when the nonce is absent.
    ///
    /// # Safety invariant
    ///
    /// `forget` must only ever be called for a nonce whose action **did not
    /// execute** — specifically, to compensate a lost optimistic-claim race
    /// (`StaleClaim`) in which the nonce was burned before the claim but the
    /// action was never dispatched. Because the action never ran, re-admitting
    /// its single-use nonce on a later pass cannot enable a real replay: the
    /// daemon that *won* the claim burns its own copy in its own cache, so
    /// single-use is preserved per execution. Calling `forget` on a nonce whose
    /// action *did* execute would reopen a replay window and is a bug.
    pub fn forget(&mut self, nonce: &str) -> Result<(), ReplayError> {
        if self.nonces.remove(nonce).is_some() {
            self.persist()?;
        }
        Ok(())
    }

    /// Remove all entries whose expiry is at or before `now`.
    fn prune_expired(&mut self, now: i64) {
        self.nonces.retain(|_, &mut exp| exp > now);
    }

    /// Persist the cache atomically with `0600` permissions.
    fn persist(&self) -> Result<(), ReplayError> {
        if let Some(parent) = self.path.parent() {
            ensure_dir(parent).map_err(|e| ReplayError::Io(e.kind()))?;
        }
        let stored = StoredCache {
            capacity: self.capacity,
            nonces: self.nonces.clone(),
        };
        let bytes = serde_json::to_vec(&stored).expect("replay cache serializes");
        let tmp = self.path.with_extension("json.tmp");
        {
            let mut f = fs::File::create(&tmp).map_err(|e| ReplayError::Io(e.kind()))?;
            f.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|e| ReplayError::Io(e.kind()))?;
            f.write_all(&bytes).map_err(|e| ReplayError::Io(e.kind()))?;
            f.flush().map_err(|e| ReplayError::Io(e.kind()))?;
        }
        fs::rename(&tmp, &self.path).map_err(|e| ReplayError::Io(e.kind()))?;
        Ok(())
    }
}

/// Path of the quarantine sentinel for the cache at `path`: a sibling
/// `replay_cache.json.corrupt`. Its presence makes [`ReplayCache::load`] fail
/// closed (returning [`ReplayError::Corrupt`]) until an operator clears it.
/// Centralized so the load-time check and the rename-aside can never drift.
fn quarantine_path(path: &Path) -> PathBuf {
    path.with_extension("json.corrupt")
}

/// Best-effort: move a corrupt cache file aside to the sibling
/// [`quarantine_path`] so its bytes survive for inspection instead of being
/// silently overwritten by the next `persist`.
///
/// Never panics and never logs file contents (only the path, architecture
/// §13.6); a failed rename is logged at `debug` and the caller still fails
/// closed. After a successful rename the original path is absent, but
/// [`ReplayCache::load`] keeps failing closed because it returns
/// [`ReplayError::Corrupt`] while the quarantine sentinel exists — it never
/// treats the now-missing path as a fresh empty cache. Replay protection is
/// re-established only once an operator clears the quarantined file.
fn quarantine_corrupt(path: &Path) {
    let quarantine = quarantine_path(path);
    if let Err(e) = fs::rename(path, &quarantine) {
        tracing::debug!(
            path = %path.display(),
            error = %e,
            "could not quarantine corrupt replay cache file"
        );
    }
}

/// Ensure `dir` exists with `0700` permissions (mirrors session storage).
fn ensure_dir(dir: &Path) -> io::Result<()> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Current time as Unix seconds.
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Parse an RFC 3339 / ISO 8601 timestamp into Unix seconds.
///
/// Supports the forms produced by mx-agent peers, e.g.
/// `2026-06-02T12:05:00Z`, `2026-06-02T12:05:00.123Z`, and numeric offsets such
/// as `2026-06-02T14:05:00+02:00`. Returns `None` for malformed input.
///
/// Exposed `pub(crate)` so the approval gate can reuse this single parser when
/// comparing an approval request's stamped `expires_at` against "now" (issue
/// #265) rather than duplicating a second RFC 3339 parser.
pub(crate) fn parse_rfc3339_to_unix(s: &str) -> Option<i64> {
    let bytes = s.as_bytes();
    // Minimum: "YYYY-MM-DDTHH:MM:SS" + zone designator.
    if s.len() < 20 {
        return None;
    }
    let year: i64 = s.get(0..4)?.parse().ok()?;
    if bytes[4] != b'-' {
        return None;
    }
    let month: u32 = s.get(5..7)?.parse().ok()?;
    if bytes[7] != b'-' {
        return None;
    }
    let day: u32 = s.get(8..10)?.parse().ok()?;
    if bytes[10] != b'T' && bytes[10] != b't' {
        return None;
    }
    let hour: u32 = s.get(11..13)?.parse().ok()?;
    if bytes[13] != b':' {
        return None;
    }
    let minute: u32 = s.get(14..16)?.parse().ok()?;
    if bytes[16] != b':' {
        return None;
    }
    let second: u32 = s.get(17..19)?.parse().ok()?;

    // Optional fractional seconds, then the mandatory time-zone designator.
    let mut rest = &s[19..];
    if let Some(after_dot) = rest.strip_prefix('.') {
        let digits = after_dot
            .as_bytes()
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count();
        if digits == 0 {
            return None;
        }
        rest = &after_dot[digits..];
    }

    let offset_secs: i64 = match rest.as_bytes().first() {
        Some(b'Z') | Some(b'z') => 0,
        Some(sign @ (b'+' | b'-')) => {
            // ±HH:MM (the colon is optional).
            let sign = if *sign == b'-' { -1 } else { 1 };
            let off_hour: i64 = rest.get(1..3)?.parse().ok()?;
            let mm_start = if rest.as_bytes().get(3) == Some(&b':') {
                4
            } else {
                3
            };
            let off_min: i64 = rest.get(mm_start..mm_start + 2)?.parse().ok()?;
            sign * (off_hour * 3600 + off_min * 60)
        }
        _ => return None,
    };

    // Basic range validation (allow second == 60 for leap seconds).
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }

    let days = days_from_civil(year, month, day);
    Some(
        days * 86_400 + i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second)
            - offset_secs,
    )
}

/// Days since the Unix epoch (1970-01-01) for a proleptic Gregorian date,
/// following Howard Hinnant's `days_from_civil` algorithm.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let m = i64::from(month);
    let doy = (153 * (if month > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A unique temporary data directory backing a [`SessionPaths`].
    ///
    /// These tests build [`SessionPaths`] directly rather than going through
    /// `SessionPaths::resolve()` so they never mutate the process environment
    /// and therefore cannot race with other modules' env-based tests.
    struct TempData {
        dir: PathBuf,
    }

    impl TempData {
        fn new(tag: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "mx-agent-replay-{}-{}-{}-{}",
                tag,
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                COUNTER.fetch_add(1, Ordering::Relaxed),
            ));
            Self { dir }
        }

        fn paths(&self) -> SessionPaths {
            SessionPaths::for_data_dir(self.dir.clone())
        }
    }

    impl Drop for TempData {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    /// A valid request is admitted once.
    #[test]
    fn fresh_request_is_admitted() {
        let data = TempData::new("fresh");
        let mut cache = ReplayCache::load(&data.paths()).unwrap();
        assert_eq!(
            cache.admit_at("nonce-a", "2026-06-02T12:05:00Z", 100),
            Ok(())
        );
        assert_eq!(cache.len(), 1);
    }

    /// Acceptance: a replayed request is denied, with no extra side effects.
    #[test]
    fn replayed_request_is_denied() {
        let data = TempData::new("replay");
        let mut cache = ReplayCache::load(&data.paths()).unwrap();
        cache
            .admit_at("nonce-r", "2026-06-02T12:05:00Z", 100)
            .unwrap();
        let len_before = cache.len();
        assert_eq!(
            cache.admit_at("nonce-r", "2026-06-02T12:05:00Z", 100),
            Err(ReplayError::Replayed)
        );
        assert_eq!(cache.len(), len_before, "replay must not change the cache");
    }

    /// Acceptance: an expired request is denied without side effects (the nonce
    /// is never recorded and the cache is unchanged).
    #[test]
    fn expired_request_is_denied_without_side_effects() {
        let data = TempData::new("expired");
        let mut cache = ReplayCache::load(&data.paths()).unwrap();
        // expires_at == 1970-01-01T00:00:10Z (10s); now is 20s -> expired.
        assert_eq!(
            cache.admit_at("nonce-e", "1970-01-01T00:00:10Z", 20),
            Err(ReplayError::Expired)
        );
        assert!(cache.is_empty(), "expired request must not be recorded");
        // No persisted state was written for the expired request.
        let file = data.paths().data_dir.join(REPLAY_CACHE_FILE);
        assert!(!file.exists(), "expired request must not persist anything");
    }

    /// A request expiring exactly at `now` is treated as expired.
    #[test]
    fn boundary_expiry_is_expired() {
        let data = TempData::new("boundary");
        let mut cache = ReplayCache::load(&data.paths()).unwrap();
        // expires_at == 100s, now == 100s.
        assert_eq!(
            cache.admit_at("nonce-b", "1970-01-01T00:01:40Z", 100),
            Err(ReplayError::Expired)
        );
    }

    /// The cache is bounded and never exceeds its capacity.
    #[test]
    fn cache_is_bounded() {
        let data = TempData::new("bounded");
        let mut cache = ReplayCache::load_with_capacity(&data.paths(), 3).unwrap();
        for i in 0..10 {
            cache
                .admit_at(&format!("nonce-{i}"), "2026-06-02T12:05:00Z", 100)
                .unwrap();
            assert!(cache.len() <= 3, "cache must respect its bound");
        }
        assert_eq!(cache.capacity(), 3);
    }

    /// Replay protection survives a restart (reload from disk).
    #[test]
    fn nonce_persists_across_reload() {
        let data = TempData::new("persist");
        // Use a far-future expiry so the entry survives the wall-clock prune
        // performed on reload.
        {
            let mut cache = ReplayCache::load(&data.paths()).unwrap();
            cache
                .admit_at("nonce-p", "2099-01-01T00:00:00Z", 100)
                .unwrap();
        }
        let mut reloaded = ReplayCache::load(&data.paths()).unwrap();
        assert_eq!(
            reloaded.admit_at("nonce-p", "2099-01-01T00:00:00Z", 100),
            Err(ReplayError::Replayed),
            "nonce must remain known after reload"
        );
    }

    /// Expired entries are pruned on load so they cannot resurrect.
    #[test]
    fn expired_entries_pruned_on_load() {
        let data = TempData::new("prune");
        {
            // now is small, so the nonce is admitted with an early expiry.
            let mut cache = ReplayCache::load(&data.paths()).unwrap();
            cache
                .admit_at("nonce-old", "1970-01-01T00:00:50Z", 10)
                .unwrap();
            assert_eq!(cache.len(), 1);
        }
        // On reload, wall-clock "now" is far past 50s, so the entry is pruned.
        let reloaded = ReplayCache::load(&data.paths()).unwrap();
        assert!(reloaded.is_empty(), "expired entry must be pruned on load");
    }

    /// The persisted cache file is not world-readable.
    #[test]
    fn persisted_cache_is_private() {
        let data = TempData::new("perms");
        let mut cache = ReplayCache::load(&data.paths()).unwrap();
        cache
            .admit_at("nonce-x", "2026-06-02T12:05:00Z", 100)
            .unwrap();
        let mode = fs::metadata(data.paths().data_dir.join(REPLAY_CACHE_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    /// A corrupt/truncated cache file fails closed (`Err(Corrupt)`) instead of
    /// silently resetting to an empty cache and forgetting every burned nonce.
    #[test]
    fn corrupt_file_fails_closed() {
        let data = TempData::new("corrupt");
        let paths = data.paths();
        ensure_dir(&paths.data_dir).unwrap();
        fs::write(
            paths.data_dir.join(REPLAY_CACHE_FILE),
            b"{ this is not valid json",
        )
        .unwrap();
        assert!(matches!(
            ReplayCache::load(&paths),
            Err(ReplayError::Corrupt)
        ));
    }

    /// After a failed corrupt load the original bytes survive at
    /// `replay_cache.json.corrupt` and no empty cache was written over them.
    #[test]
    fn corrupt_file_is_quarantined_not_overwritten() {
        let data = TempData::new("quarantine");
        let paths = data.paths();
        ensure_dir(&paths.data_dir).unwrap();
        let file = paths.data_dir.join(REPLAY_CACHE_FILE);
        let corrupt_bytes = b"not json at all".to_vec();
        fs::write(&file, &corrupt_bytes).unwrap();

        assert!(matches!(
            ReplayCache::load(&paths),
            Err(ReplayError::Corrupt)
        ));

        // The corrupt bytes are preserved aside, not overwritten with an empty
        // cache, so an operator can inspect them.
        let quarantined = paths.data_dir.join("replay_cache.json.corrupt");
        assert_eq!(fs::read(&quarantined).unwrap(), corrupt_bytes);
        // The original path is not left holding a silently reset empty cache.
        assert!(
            !file.exists(),
            "corrupt file must be moved aside, not reset in place"
        );
    }

    /// Regression: once a corrupt load has quarantined the cache, every
    /// subsequent load keeps failing closed. The renamed-aside original path
    /// must NOT be read as `NotFound` and silently resolved to a fresh empty
    /// cache — that would forget every previously burned nonce (and, within a
    /// scheduler pass, leak the emptied cache to sibling agents loading after
    /// the first).
    #[test]
    fn corrupt_quarantine_keeps_failing_closed_on_reload() {
        let data = TempData::new("requarantine");
        let paths = data.paths();
        ensure_dir(&paths.data_dir).unwrap();
        fs::write(
            paths.data_dir.join(REPLAY_CACHE_FILE),
            b"{ truncated not json",
        )
        .unwrap();

        // First load quarantines the corrupt file and fails closed.
        assert!(matches!(
            ReplayCache::load(&paths),
            Err(ReplayError::Corrupt)
        ));
        // The original path is now absent (renamed to the sentinel), yet every
        // later load must STILL fail closed rather than yield an empty cache.
        assert!(
            !paths.data_dir.join(REPLAY_CACHE_FILE).exists(),
            "corrupt file was moved aside"
        );
        for _ in 0..3 {
            assert!(
                matches!(ReplayCache::load(&paths), Err(ReplayError::Corrupt)),
                "load must keep failing closed while the quarantine sentinel exists"
            );
        }
    }

    /// Operator escape hatch: clearing the quarantined file lets `load` resume
    /// with a fresh (empty) cache, re-establishing replay protection.
    #[test]
    fn clearing_quarantine_resets_to_fresh_cache() {
        let data = TempData::new("clearquarantine");
        let paths = data.paths();
        ensure_dir(&paths.data_dir).unwrap();
        fs::write(paths.data_dir.join(REPLAY_CACHE_FILE), b"not json").unwrap();
        assert!(matches!(
            ReplayCache::load(&paths),
            Err(ReplayError::Corrupt)
        ));

        // The operator moves the quarantined file aside.
        fs::remove_file(paths.data_dir.join("replay_cache.json.corrupt")).unwrap();

        // Now load succeeds with a fresh empty cache and can admit again.
        let mut cache = ReplayCache::load(&paths).unwrap();
        assert!(cache.is_empty());
        assert_eq!(
            cache.admit_at("nonce-after-reset", "2099-01-01T00:00:00Z", 100),
            Ok(())
        );
    }

    /// A genuine (non-`NotFound`) IO error surfaces as `Err(Io(..))` rather than
    /// being treated as an empty cache.
    #[test]
    fn load_io_error_surfaces_err() {
        let data = TempData::new("ioerr");
        let paths = data.paths();
        ensure_dir(&paths.data_dir).unwrap();
        // Make the cache path a directory so `fs::read` fails with a
        // non-`NotFound` IO error instead of yielding bytes to parse.
        fs::create_dir(paths.data_dir.join(REPLAY_CACHE_FILE)).unwrap();
        assert!(matches!(ReplayCache::load(&paths), Err(ReplayError::Io(_))));
    }

    /// `forget` removes a burned nonce (persisting the change) so the action can
    /// be re-admitted; forgetting an absent nonce is a no-op `Ok`.
    #[test]
    fn forget_removes_and_persists() {
        let data = TempData::new("forget");
        let mut cache = ReplayCache::load(&data.paths()).unwrap();
        cache
            .admit_at("nonce-f", "2099-01-01T00:00:00Z", 100)
            .unwrap();
        assert_eq!(cache.len(), 1);
        // Forgetting an absent nonce is a no-op and still `Ok`.
        assert_eq!(cache.forget("never-seen"), Ok(()));
        assert_eq!(cache.len(), 1);
        // Forgetting the burned nonce removes it and persists the change.
        assert_eq!(cache.forget("nonce-f"), Ok(()));
        assert!(cache.is_empty());
        // A reload confirms the persisted removal: the nonce is admissible again.
        let mut reloaded = ReplayCache::load(&data.paths()).unwrap();
        assert_eq!(
            reloaded.admit_at("nonce-f", "2099-01-01T00:00:00Z", 100),
            Ok(())
        );
    }

    #[test]
    fn malformed_timestamp_is_rejected() {
        let data = TempData::new("malformed");
        let mut cache = ReplayCache::load(&data.paths()).unwrap();
        assert_eq!(
            cache.admit_at("nonce-m", "not-a-timestamp", 0),
            Err(ReplayError::MalformedTimestamp)
        );
        assert!(cache.is_empty());
    }

    #[test]
    fn rfc3339_parsing() {
        assert_eq!(parse_rfc3339_to_unix("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339_to_unix("1970-01-01T00:00:10Z"), Some(10));
        assert_eq!(
            parse_rfc3339_to_unix("2000-01-01T00:00:00Z"),
            Some(946_684_800)
        );
        // Fractional seconds are accepted and truncated to whole seconds.
        assert_eq!(
            parse_rfc3339_to_unix("2000-01-01T00:00:00.500Z"),
            Some(946_684_800)
        );
        // Numeric offset: 14:00+02:00 == 12:00Z.
        assert_eq!(
            parse_rfc3339_to_unix("2000-01-01T02:00:00+02:00"),
            parse_rfc3339_to_unix("2000-01-01T00:00:00Z")
        );
        assert_eq!(parse_rfc3339_to_unix("garbage"), None);
        assert_eq!(parse_rfc3339_to_unix("2000-13-01T00:00:00Z"), None);
    }
}
