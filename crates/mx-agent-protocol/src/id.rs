//! Identifier generation and validation for mx-agent entities.
//!
//! IDs are sortable: each is a short type prefix followed by a
//! [ULID](https://github.com/ulid/spec) (26 Crockford base32 characters). The
//! ULID's leading timestamp makes IDs lexicographically sortable by creation
//! time, matching the `inv_01HZ...` style used in `docs/architecture.md`.
//!
//! ```
//! use mx_agent_protocol::id::{generate, validate, IdKind};
//!
//! let id = generate(IdKind::Invocation);
//! assert!(id.starts_with("inv_"));
//! assert!(validate(IdKind::Invocation, &id).is_ok());
//! ```

use std::fmt;

use ulid::Ulid;

/// Number of characters in a canonical ULID string.
pub const ULID_LEN: usize = 26;

/// The kind of entity an identifier refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdKind {
    /// A local agent persona.
    Agent,
    /// A durable task (DAG node).
    Task,
    /// A request (e.g. exec or approval request).
    Request,
    /// A remote call/exec invocation.
    Invocation,
    /// A shared context object.
    Context,
}

impl IdKind {
    /// The prefix (including the trailing underscore) for this kind.
    pub const fn prefix(self) -> &'static str {
        match self {
            IdKind::Agent => "agt_",
            IdKind::Task => "task_",
            IdKind::Request => "req_",
            IdKind::Invocation => "inv_",
            IdKind::Context => "ctx_",
        }
    }

    /// All ID kinds, for exhaustive iteration in tests and validators.
    pub const ALL: [IdKind; 5] = [
        IdKind::Agent,
        IdKind::Task,
        IdKind::Request,
        IdKind::Invocation,
        IdKind::Context,
    ];
}

/// Error returned when an identifier fails validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdError {
    /// The string does not start with the expected prefix.
    WrongPrefix {
        /// Expected prefix.
        expected: &'static str,
    },
    /// The portion after the prefix is not a valid ULID.
    InvalidUlid,
}

impl fmt::Display for IdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdError::WrongPrefix { expected } => {
                write!(f, "identifier must start with prefix `{expected}`")
            }
            IdError::InvalidUlid => write!(f, "identifier body is not a valid ULID"),
        }
    }
}

impl std::error::Error for IdError {}

/// Generate a new sortable identifier for `kind`.
///
/// The result is the kind's [`IdKind::prefix`] followed by a freshly minted
/// ULID, e.g. `inv_01J0Z3R8XB9V2K5N7Q1Wced4ab`.
pub fn generate(kind: IdKind) -> String {
    format!("{}{}", kind.prefix(), Ulid::new())
}

/// Generate a new agent identifier (`agt_...`).
pub fn generate_agent_id() -> String {
    generate(IdKind::Agent)
}

/// Generate a new task identifier (`task_...`).
pub fn generate_task_id() -> String {
    generate(IdKind::Task)
}

/// Generate a new request identifier (`req_...`).
pub fn generate_request_id() -> String {
    generate(IdKind::Request)
}

/// Generate a new invocation identifier (`inv_...`).
pub fn generate_invocation_id() -> String {
    generate(IdKind::Invocation)
}

/// Generate a new context identifier (`ctx_...`).
pub fn generate_context_id() -> String {
    generate(IdKind::Context)
}

/// Validate that `id` is a well-formed identifier of the given `kind`.
///
/// Checks that the string carries the expected prefix and that the remaining
/// body is a syntactically valid ULID.
pub fn validate(kind: IdKind, id: &str) -> Result<(), IdError> {
    let prefix = kind.prefix();
    let body = id
        .strip_prefix(prefix)
        .ok_or(IdError::WrongPrefix { expected: prefix })?;
    Ulid::from_string(body).map_err(|_| IdError::InvalidUlid)?;
    Ok(())
}

/// Determine the [`IdKind`] of `id` and validate its ULID body.
///
/// Returns `None` if the string carries no known prefix or has an invalid body.
pub fn classify(id: &str) -> Option<IdKind> {
    IdKind::ALL
        .into_iter()
        .find(|&kind| validate(kind, id).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn generated_ids_carry_expected_prefix() {
        assert!(generate_agent_id().starts_with("agt_"));
        assert!(generate_task_id().starts_with("task_"));
        assert!(generate_request_id().starts_with("req_"));
        assert!(generate_invocation_id().starts_with("inv_"));
        assert!(generate_context_id().starts_with("ctx_"));
    }

    #[test]
    fn generated_ids_validate_for_their_kind() {
        for kind in IdKind::ALL {
            let id = generate(kind);
            assert_eq!(validate(kind, &id), Ok(()), "{id} should validate");
            assert_eq!(classify(&id), Some(kind));
        }
    }

    #[test]
    fn generated_ids_are_unique() {
        let mut seen = HashSet::new();
        for _ in 0..10_000 {
            assert!(seen.insert(generate(IdKind::Invocation)), "duplicate id");
        }
        assert_eq!(seen.len(), 10_000);
    }

    #[test]
    fn ids_are_sortable_by_creation_time() {
        // ULIDs encode a millisecond timestamp in their leading characters, so
        // IDs minted in distinct milliseconds sort by creation time. (Within a
        // single millisecond the random tail makes ordering unspecified.)
        let mut prev = generate(IdKind::Task);
        for _ in 0..10 {
            std::thread::sleep(std::time::Duration::from_millis(2));
            let next = generate(IdKind::Task);
            assert!(prev < next, "{prev} should sort before {next}");
            prev = next;
        }
    }

    #[test]
    fn wrong_prefix_is_rejected() {
        let inv = generate(IdKind::Invocation);
        // Body is a valid ULID, but the prefix is wrong for Request.
        match validate(IdKind::Request, &inv) {
            Err(IdError::WrongPrefix { expected }) => assert_eq!(expected, "req_"),
            other => panic!("expected WrongPrefix, got {other:?}"),
        }
    }

    #[test]
    fn invalid_ulid_body_is_rejected() {
        assert_eq!(
            validate(IdKind::Invocation, "inv_not-a-ulid"),
            Err(IdError::InvalidUlid)
        );
        // Missing prefix entirely.
        assert!(matches!(
            validate(IdKind::Agent, "developer-pi"),
            Err(IdError::WrongPrefix { .. })
        ));
        // Empty and prefix-only strings.
        assert!(validate(IdKind::Context, "").is_err());
        assert!(validate(IdKind::Context, "ctx_").is_err());
        // classify rejects unknown junk.
        assert_eq!(classify("garbage"), None);
    }
}
