//! Local trusted-key store (architecture §13.2).
//!
//! Trust decisions for privileged requests (`exec`, `call`, `task`, and further
//! `trust` changes) are anchored in a daemon-owned store of approved agent
//! signing keys. A key is identified by its stable key identifier
//! (`mxagent-ed25519:<base64>`) and the agent it belongs to.
//!
//! The store is persisted as JSON in the daemon's private data directory with
//! `0600` permissions, so trust survives a daemon restart and is never
//! world-readable. Approving a key records it as [`TrustStatus::Trusted`];
//! revoking flips it to [`TrustStatus::Revoked`] (retaining the record so the
//! revocation is auditable). Only keys that are present and trusted authorize a
//! privileged request — unknown and revoked keys are rejected.
//!
//! This module owns the *local* trust state only. Optional publication of trust
//! state to a Matrix room is a later, separate concern.

use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::session::SessionPaths;
use crate::signing::KEY_ID_PREFIX;

/// Trust status recorded for a stored key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustStatus {
    /// The key is approved and may authorize privileged requests.
    Trusted,
    /// The key was approved previously but has since been revoked.
    Revoked,
}

impl fmt::Display for TrustStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Trusted => f.write_str("trusted"),
            Self::Revoked => f.write_str("revoked"),
        }
    }
}

/// A single trust record for an `(agent_id, key_id)` pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustEntry {
    /// Agent identifier the key belongs to.
    pub agent_id: String,
    /// Stable key identifier (`mxagent-ed25519:<base64>`).
    pub key_id: String,
    /// Public-key fingerprint (`SHA256:<base64>`).
    pub fingerprint: String,
    /// Current trust status.
    pub status: TrustStatus,
    /// Workspace room the trust was scoped to, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub room: Option<String>,
    /// Identity that approved the key, if recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_by: Option<String>,
    /// Approval time as Unix seconds.
    pub created_at: u64,
    /// Revocation time as Unix seconds, if revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<u64>,
}

impl TrustEntry {
    /// Whether this entry currently authorizes privileged requests.
    pub fn is_trusted(&self) -> bool {
        self.status == TrustStatus::Trusted
    }
}

/// An in-memory view of the local trust store.
///
/// Load with [`TrustStore::load`], mutate with [`TrustStore::approve`] /
/// [`TrustStore::revoke`], then persist with [`TrustStore::save`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustStore {
    /// Trust records, one per `(agent_id, key_id)` pair.
    #[serde(default)]
    entries: Vec<TrustEntry>,
}

/// The path to the persisted trust store file.
fn trust_store_file(paths: &SessionPaths) -> PathBuf {
    paths.data_dir.join("trust.json")
}

/// Current time as Unix seconds.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Derive the `SHA256:<base64>` fingerprint from a `mxagent-ed25519:<base64>`
/// key identifier. The two share the same base64 digest, so the fingerprint is
/// recoverable from the key id without the public key bytes.
pub fn fingerprint_from_key_id(key_id: &str) -> Option<String> {
    let suffix = key_id.strip_prefix(KEY_ID_PREFIX)?.strip_prefix(':')?;
    if suffix.is_empty() {
        return None;
    }
    Some(format!("SHA256:{suffix}"))
}

impl TrustStore {
    /// Load the trust store from disk, returning an empty store on first run.
    pub fn load(paths: &SessionPaths) -> io::Result<Self> {
        match fs::read(trust_store_file(paths)) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e),
        }
    }

    /// Persist the trust store atomically with `0600` permissions.
    pub fn save(&self, paths: &SessionPaths) -> io::Result<()> {
        paths.ensure_data_dir()?;
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let file = trust_store_file(paths);
        let tmp = file.with_extension("json.tmp");
        {
            let mut f = fs::File::create(&tmp)?;
            f.set_permissions(fs::Permissions::from_mode(0o600))?;
            f.write_all(&bytes)?;
            f.flush()?;
        }
        fs::rename(&tmp, &file)?;
        Ok(())
    }

    /// All trust records.
    pub fn entries(&self) -> &[TrustEntry] {
        &self.entries
    }

    /// Find the index of the record for an `(agent_id, key_id)` pair.
    fn position(&self, agent_id: &str, key_id: &str) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.agent_id == agent_id && e.key_id == key_id)
    }

    /// Borrow the trust record for an `(agent_id, key_id)` pair, if one exists.
    ///
    /// Unlike [`TrustStore::is_trusted`], this returns the record regardless of
    /// its status, so callers can distinguish "no local opinion" (returns
    /// `None`) from an explicit local revocation (returns a record with
    /// [`TrustStatus::Revoked`]). This distinction is what lets the local store
    /// act as the final authority over room-published trust.
    pub fn entry(&self, agent_id: &str, key_id: &str) -> Option<&TrustEntry> {
        self.position(agent_id, key_id)
            .map(|idx| &self.entries[idx])
    }

    /// Approve a signing key for an agent.
    ///
    /// Inserts a new trusted record or, if the pair already exists, refreshes it
    /// to [`TrustStatus::Trusted`] (clearing any prior revocation). When
    /// `fingerprint` is `None` it is derived from `key_id`. Returns the stored
    /// entry.
    pub fn approve(
        &mut self,
        agent_id: impl Into<String>,
        key_id: impl Into<String>,
        fingerprint: Option<String>,
        room: Option<String>,
        trusted_by: Option<String>,
    ) -> TrustEntry {
        let agent_id = agent_id.into();
        let key_id = key_id.into();
        let fingerprint = fingerprint
            .or_else(|| fingerprint_from_key_id(&key_id))
            .unwrap_or_default();
        let now = now_unix();

        if let Some(idx) = self.position(&agent_id, &key_id) {
            let entry = &mut self.entries[idx];
            entry.fingerprint = fingerprint;
            entry.status = TrustStatus::Trusted;
            entry.revoked_at = None;
            if room.is_some() {
                entry.room = room;
            }
            if trusted_by.is_some() {
                entry.trusted_by = trusted_by;
            }
            entry.clone()
        } else {
            let entry = TrustEntry {
                agent_id,
                key_id,
                fingerprint,
                status: TrustStatus::Trusted,
                room,
                trusted_by,
                created_at: now,
                revoked_at: None,
            };
            self.entries.push(entry.clone());
            entry
        }
    }

    /// Revoke a previously approved key.
    ///
    /// Marks the matching record as [`TrustStatus::Revoked`] and stamps
    /// `revoked_at`. Returns the updated entry, or `None` if no record exists
    /// for the pair.
    pub fn revoke(&mut self, agent_id: &str, key_id: &str) -> Option<TrustEntry> {
        let idx = self.position(agent_id, key_id)?;
        let entry = &mut self.entries[idx];
        entry.status = TrustStatus::Revoked;
        entry.revoked_at = Some(now_unix());
        Some(entry.clone())
    }

    /// Whether the given `(agent_id, key_id)` pair currently authorizes
    /// privileged requests. Unknown and revoked keys return `false`.
    pub fn is_trusted(&self, agent_id: &str, key_id: &str) -> bool {
        self.position(agent_id, key_id)
            .map(|idx| self.entries[idx].is_trusted())
            .unwrap_or(false)
    }

    /// Whether the given key identifier is trusted for any agent. Useful when a
    /// privileged request is authenticated by signing key alone.
    pub fn is_key_trusted(&self, key_id: &str) -> bool {
        self.entries
            .iter()
            .any(|e| e.key_id == key_id && e.is_trusted())
    }
}

/// Load the trust store, apply `f`, and persist the result atomically — the
/// whole `load → modify → save` round trip under the data-dir advisory write
/// lock so concurrent `trust approve` / `trust revoke` invocations cannot
/// lost-update `trust.json` and silently drop a revocation (issue #316).
///
/// This is the only correct way to mutate the persisted store from a CLI-local
/// command or a daemon trust path: two unlocked `load → mutate → save` round
/// trips can interleave so the second writer's save clobbers the first writer's
/// change, dropping it. Holding the lock across the whole round trip serializes
/// them, so both updates are reflected (the revocation is never lost). The
/// closure's return value (e.g. the resulting [`TrustEntry`], or `None` for a
/// revoke of an unknown key) is returned on success.
///
/// [`TrustStore::load`] stays lock-free — reads tolerate a concurrent atomic
/// rename — and [`TrustStore::save`] must stay lock-free too so there is no
/// nested acquisition inside this helper.
pub fn update_trust_store<R>(
    paths: &SessionPaths,
    f: impl FnOnce(&mut TrustStore) -> R,
) -> io::Result<R> {
    crate::session::with_data_dir_write_lock(paths, || {
        let mut store = TrustStore::load(paths)?;
        let result = f(&mut store);
        store.save(paths)?;
        Ok(result)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    struct TempData {
        dir: PathBuf,
        _guard: MutexGuard<'static, ()>,
    }

    impl TempData {
        fn new(tag: &str) -> Self {
            let guard = env_lock();
            let dir = std::env::temp_dir().join(format!(
                "mx-agent-trust-{}-{}-{}",
                tag,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::env::set_var(crate::session::ENV_DATA_DIR, &dir);
            Self { dir, _guard: guard }
        }
    }

    impl Drop for TempData {
        fn drop(&mut self) {
            std::env::remove_var(crate::session::ENV_DATA_DIR);
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    const KEY: &str = "mxagent-ed25519:abc123";
    const AGENT: &str = "developer-pi";

    #[test]
    fn fingerprint_is_derived_from_key_id() {
        assert_eq!(
            fingerprint_from_key_id("mxagent-ed25519:abc123").as_deref(),
            Some("SHA256:abc123")
        );
        assert_eq!(fingerprint_from_key_id("not-a-key-id"), None);
        assert_eq!(fingerprint_from_key_id("mxagent-ed25519:"), None);
    }

    #[test]
    fn approved_key_is_trusted_revoked_is_rejected() {
        let mut store = TrustStore::default();
        // Unknown keys are never trusted.
        assert!(!store.is_trusted(AGENT, KEY));

        let entry = store.approve(AGENT, KEY, None, None, None);
        assert_eq!(entry.status, TrustStatus::Trusted);
        assert_eq!(entry.fingerprint, "SHA256:abc123");
        // Approved keys authorize privileged requests.
        assert!(store.is_trusted(AGENT, KEY));
        assert!(store.is_key_trusted(KEY));

        // Revoked keys are rejected.
        let revoked = store.revoke(AGENT, KEY).expect("entry exists");
        assert_eq!(revoked.status, TrustStatus::Revoked);
        assert!(revoked.revoked_at.is_some());
        assert!(!store.is_trusted(AGENT, KEY));
        assert!(!store.is_key_trusted(KEY));
    }

    #[test]
    fn revoking_unknown_key_returns_none() {
        let mut store = TrustStore::default();
        assert!(store.revoke(AGENT, KEY).is_none());
    }

    #[test]
    fn re_approving_clears_revocation() {
        let mut store = TrustStore::default();
        store.approve(AGENT, KEY, None, None, None);
        store.revoke(AGENT, KEY);
        let entry = store.approve(AGENT, KEY, None, None, None);
        assert_eq!(entry.status, TrustStatus::Trusted);
        assert!(entry.revoked_at.is_none());
        assert!(store.is_trusted(AGENT, KEY));
        // Still a single record for the pair.
        assert_eq!(store.entries().len(), 1);
    }

    #[test]
    fn trust_survives_daemon_restart() {
        let _data = TempData::new("restart");
        let paths = SessionPaths::resolve();

        let mut store = TrustStore::load(&paths).unwrap();
        store.approve(
            AGENT,
            KEY,
            None,
            Some("!abc:matrix.org".to_string()),
            Some("@owner:matrix.org".to_string()),
        );
        store.approve("other", "mxagent-ed25519:def456", None, None, None);
        store.revoke("other", "mxagent-ed25519:def456");
        store.save(&paths).unwrap();

        // Simulate a restart by reloading the store from disk afresh.
        let reloaded = TrustStore::load(&paths).unwrap();
        assert!(reloaded.is_trusted(AGENT, KEY));
        assert!(!reloaded.is_trusted("other", "mxagent-ed25519:def456"));
        let entry = reloaded
            .entries()
            .iter()
            .find(|e| e.agent_id == AGENT)
            .unwrap();
        assert_eq!(entry.room.as_deref(), Some("!abc:matrix.org"));
        assert_eq!(entry.trusted_by.as_deref(), Some("@owner:matrix.org"));
    }

    #[test]
    fn trust_store_file_is_private() {
        let _data = TempData::new("perms");
        let paths = SessionPaths::resolve();
        let mut store = TrustStore::default();
        store.approve(AGENT, KEY, None, None, None);
        store.save(&paths).unwrap();
        let mode = fs::metadata(trust_store_file(&paths))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "trust store must be private");
    }

    #[test]
    fn missing_store_loads_empty() {
        let _data = TempData::new("missing");
        let paths = SessionPaths::resolve();
        let store = TrustStore::load(&paths).unwrap();
        assert!(store.entries().is_empty());
    }

    /// A unique, per-call data dir that does not touch `MX_AGENT_DATA_DIR` (and
    /// so the env lock), for tests that spawn threads sharing one explicit dir.
    fn unique_temp_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "mx-agent-trustlock-{}-{}-{}",
            std::process::id(),
            n,
            tag
        ))
    }

    #[test]
    fn update_trust_store_persists_round_trip() {
        let dir = unique_temp_dir("roundtrip");
        let paths = SessionPaths::for_data_dir(dir.clone());
        paths.ensure_data_dir().unwrap();
        let entry = update_trust_store(&paths, |store| store.approve(AGENT, KEY, None, None, None))
            .unwrap();
        assert_eq!(entry.status, TrustStatus::Trusted);
        assert!(TrustStore::load(&paths).unwrap().is_trusted(AGENT, KEY));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_update_trust_store_preserves_both_updates() {
        // Issue #316: a concurrent approve (of one key) and revoke (of another)
        // running through `update_trust_store` must both land — the lock-held
        // load-modify-save round trip means neither lost-updates the other, so a
        // revocation is never silently dropped.
        use std::sync::{Arc, Barrier};

        let dir = unique_temp_dir("race");
        let paths = Arc::new(SessionPaths::for_data_dir(dir.clone()));
        paths.ensure_data_dir().unwrap();
        // Seed the key that will be revoked.
        update_trust_store(&paths, |store| {
            store.approve(AGENT, KEY, None, None, None);
        })
        .unwrap();

        let barrier = Arc::new(Barrier::new(2));
        let p_approve = Arc::clone(&paths);
        let b_approve = Arc::clone(&barrier);
        let approver = std::thread::spawn(move || {
            b_approve.wait();
            for _ in 0..50 {
                update_trust_store(&p_approve, |store| {
                    store.approve("late", "mxagent-ed25519:late", None, None, None);
                })
                .unwrap();
            }
        });
        let p_revoke = Arc::clone(&paths);
        let b_revoke = Arc::clone(&barrier);
        let revoker = std::thread::spawn(move || {
            b_revoke.wait();
            for _ in 0..50 {
                update_trust_store(&p_revoke, |store| {
                    store.revoke(AGENT, KEY);
                })
                .unwrap();
            }
        });
        approver.join().unwrap();
        revoker.join().unwrap();

        let store = TrustStore::load(&paths).unwrap();
        assert_eq!(
            store.entry(AGENT, KEY).map(|e| e.status),
            Some(TrustStatus::Revoked),
            "the revocation must never be lost"
        );
        assert!(
            store.is_key_trusted("mxagent-ed25519:late"),
            "the concurrent approve must also be preserved"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
