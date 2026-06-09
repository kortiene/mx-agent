//! Canonical JSON serialization for mx-agent signing (architecture §13, §15).
//!
//! Privileged requests are signed over a deterministic byte representation of
//! their `content` so that any two peers compute identical bytes for the same
//! logical payload. This module defines that representation.
//!
//! The encoding follows the same rules as Matrix canonical JSON
//! (<https://spec.matrix.org/latest/appendices/#canonical-json>):
//!
//! - object keys are sorted lexicographically by their Unicode code points;
//! - no insignificant whitespace is emitted between tokens;
//! - strings use standard JSON escaping (UTF-8 output);
//! - arrays preserve their element order;
//! - numbers must be integers — floating-point values (including whole-valued
//!   floats such as `1.0`) are **rejected**, never coerced, because Matrix
//!   canonical JSON forbids floats. Encoding a float-bearing value therefore
//!   fails with [`CanonicalJsonError::NonIntegerNumber`] rather than producing
//!   bytes a strict Matrix peer would compute differently.
//!
//! Because the representation is deterministic, signing and verification can be
//! performed independently on either side of a Matrix room and still agree on
//! the exact bytes that were signed.

use std::fmt;

use serde_json::Value;

/// Error returned when a value cannot be encoded as canonical JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalJsonError {
    /// A `Number` was floating-point. Matrix canonical JSON permits only
    /// integers, so floats (including whole-valued floats like `1.0`) are
    /// rejected rather than serialized.
    NonIntegerNumber,
}

impl fmt::Display for CanonicalJsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonIntegerNumber => write!(f, "canonical JSON forbids non-integer numbers"),
        }
    }
}

impl std::error::Error for CanonicalJsonError {}

/// Serialize `value` to its canonical JSON string representation.
///
/// The result is deterministic: equal logical values always produce identical
/// strings regardless of the order in which object keys were inserted.
///
/// Returns [`CanonicalJsonError::NonIntegerNumber`] if `value` contains a
/// floating-point number anywhere in its structure.
pub fn to_canonical_string(value: &Value) -> Result<String, CanonicalJsonError> {
    let mut out = String::new();
    write_value(value, &mut out)?;
    Ok(out)
}

/// Serialize `value` to canonical JSON bytes (UTF-8 encoding of
/// [`to_canonical_string`]). These are the exact bytes that get signed.
///
/// Returns [`CanonicalJsonError::NonIntegerNumber`] if `value` contains a
/// floating-point number anywhere in its structure.
pub fn to_canonical_bytes(value: &Value) -> Result<Vec<u8>, CanonicalJsonError> {
    Ok(to_canonical_string(value)?.into_bytes())
}

fn write_value(value: &Value, out: &mut String) -> Result<(), CanonicalJsonError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => {
            // `serde_json` (with default features) reports `is_f64()` exactly
            // for values that are not representable as `i64`/`u64`, i.e. float
            // literals such as `1.0` or `3.14`. NaN/Inf are already refused at
            // parse time. Fail closed rather than emit non-canonical bytes.
            if n.is_f64() {
                return Err(CanonicalJsonError::NonIntegerNumber);
            }
            out.push_str(&n.to_string());
        }
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // `serde_json::Map` keys are iterated in sorted order by default,
            // but sort explicitly so the canonical form does not depend on the
            // crate's feature flags (e.g. `preserve_order`).
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_value(&map[*key], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Write a JSON string literal (including surrounding quotes) using serde_json's
/// standard escaping, which yields valid canonical-JSON string tokens.
fn write_string(s: &str, out: &mut String) {
    // Serializing a `&str` cannot fail.
    let encoded = serde_json::to_string(s).expect("string serialization is infallible");
    out.push_str(&encoded);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn object_keys_are_sorted() {
        let value = json!({ "b": 1, "a": 2, "c": 3 });
        assert_eq!(
            to_canonical_string(&value).unwrap(),
            r#"{"a":2,"b":1,"c":3}"#
        );
    }

    #[test]
    fn key_order_does_not_change_output() {
        let one = json!({ "z": 1, "a": 2, "m": 3 });
        let two = json!({ "a": 2, "m": 3, "z": 1 });
        assert_eq!(
            to_canonical_string(&one).unwrap(),
            to_canonical_string(&two).unwrap()
        );
    }

    #[test]
    fn nested_objects_are_sorted_recursively() {
        let value = json!({
            "outer": { "y": 1, "x": 2 },
            "list": [ { "b": 1, "a": 2 } ]
        });
        assert_eq!(
            to_canonical_string(&value).unwrap(),
            r#"{"list":[{"a":2,"b":1}],"outer":{"x":2,"y":1}}"#
        );
    }

    #[test]
    fn no_insignificant_whitespace() {
        let value = json!({ "a": [1, 2, 3], "b": { "c": "d" } });
        let s = to_canonical_string(&value).unwrap();
        assert!(!s.contains(' '));
        assert!(!s.contains('\n'));
    }

    #[test]
    fn arrays_preserve_order() {
        let value = json!([3, 1, 2]);
        assert_eq!(to_canonical_string(&value).unwrap(), "[3,1,2]");
    }

    #[test]
    fn strings_are_escaped() {
        let value = json!({ "msg": "line1\nline2\t\"q\"" });
        assert_eq!(
            to_canonical_string(&value).unwrap(),
            r#"{"msg":"line1\nline2\t\"q\""}"#
        );
    }

    #[test]
    fn scalars_round_trip() {
        assert_eq!(to_canonical_string(&json!(null)).unwrap(), "null");
        assert_eq!(to_canonical_string(&json!(true)).unwrap(), "true");
        assert_eq!(to_canonical_string(&json!(false)).unwrap(), "false");
        assert_eq!(to_canonical_string(&json!(42)).unwrap(), "42");
        assert_eq!(to_canonical_string(&json!(-7)).unwrap(), "-7");
        assert_eq!(to_canonical_string(&json!("hi")).unwrap(), r#""hi""#);
    }

    #[test]
    fn integers_still_encode() {
        // Regression guard: integer numbers (including large i64/u64 extremes)
        // must canonicalize to their plain decimal strings, byte-for-byte as
        // before, so the float rejection does not perturb signing vectors.
        assert_eq!(to_canonical_string(&json!(0)).unwrap(), "0");
        assert_eq!(to_canonical_string(&json!(42)).unwrap(), "42");
        assert_eq!(to_canonical_string(&json!(-7)).unwrap(), "-7");
        assert_eq!(
            to_canonical_string(&json!(i64::MIN)).unwrap(),
            i64::MIN.to_string()
        );
        assert_eq!(
            to_canonical_string(&json!(u64::MAX)).unwrap(),
            u64::MAX.to_string()
        );
    }

    #[test]
    fn float_number_is_rejected() {
        let value = json!({ "x": 1.5 });
        assert_eq!(
            to_canonical_string(&value),
            Err(CanonicalJsonError::NonIntegerNumber)
        );
        assert_eq!(
            to_canonical_bytes(&value),
            Err(CanonicalJsonError::NonIntegerNumber)
        );
    }

    #[test]
    fn whole_valued_float_is_rejected() {
        // A float that happens to be whole (`1.0`) must be rejected, not
        // silently coerced to the integer `"1"`.
        let value = json!(1.0);
        assert!(value.is_f64(), "json!(1.0) is stored as an f64");
        assert_eq!(
            to_canonical_string(&value),
            Err(CanonicalJsonError::NonIntegerNumber)
        );
    }

    #[test]
    fn nested_float_is_rejected() {
        // Rejection must propagate through arrays and objects, not only at the
        // top level.
        let in_array = json!([1, 2, 3.5]);
        assert_eq!(
            to_canonical_string(&in_array),
            Err(CanonicalJsonError::NonIntegerNumber)
        );
        let in_object = json!({ "outer": { "inner": 0.1 } });
        assert_eq!(
            to_canonical_string(&in_object),
            Err(CanonicalJsonError::NonIntegerNumber)
        );
    }

    #[test]
    fn bytes_match_string_utf8() {
        let value = json!({ "k": "v" });
        assert_eq!(
            to_canonical_bytes(&value).unwrap(),
            to_canonical_string(&value).unwrap().into_bytes()
        );
    }

    #[test]
    fn error_display_message() {
        // The error message is part of the public contract: callers log it and
        // the signing module forwards it via `SignatureError::NonCanonical`.
        let msg = CanonicalJsonError::NonIntegerNumber.to_string();
        assert_eq!(msg, "canonical JSON forbids non-integer numbers");
    }

    #[test]
    fn empty_object_and_array() {
        assert_eq!(to_canonical_string(&json!({})).unwrap(), "{}");
        assert_eq!(to_canonical_string(&json!([])).unwrap(), "[]");
    }

    #[test]
    fn float_via_number_constructor_is_rejected() {
        // Construct the float `Value` through `serde_json::Number::from_f64`
        // rather than the `json!()` macro to confirm the `is_f64()` guard works
        // at the type level, not just for macro-produced literals.
        let n = serde_json::Number::from_f64(1.5).expect("1.5 is a finite, representable f64");
        let value = Value::Number(n);
        assert_eq!(
            to_canonical_string(&value),
            Err(CanonicalJsonError::NonIntegerNumber)
        );
        assert_eq!(
            to_canonical_bytes(&value),
            Err(CanonicalJsonError::NonIntegerNumber)
        );
    }
}
