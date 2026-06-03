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
//! - arrays preserve their element order.
//!
//! Because the representation is deterministic, signing and verification can be
//! performed independently on either side of a Matrix room and still agree on
//! the exact bytes that were signed.

use serde_json::Value;

/// Serialize `value` to its canonical JSON string representation.
///
/// The result is deterministic: equal logical values always produce identical
/// strings regardless of the order in which object keys were inserted.
pub fn to_canonical_string(value: &Value) -> String {
    let mut out = String::new();
    write_value(value, &mut out);
    out
}

/// Serialize `value` to canonical JSON bytes (UTF-8 encoding of
/// [`to_canonical_string`]). These are the exact bytes that get signed.
pub fn to_canonical_bytes(value: &Value) -> Vec<u8> {
    to_canonical_string(value).into_bytes()
}

fn write_value(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out);
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
                write_value(&map[*key], out);
            }
            out.push('}');
        }
    }
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
        assert_eq!(to_canonical_string(&value), r#"{"a":2,"b":1,"c":3}"#);
    }

    #[test]
    fn key_order_does_not_change_output() {
        let one = json!({ "z": 1, "a": 2, "m": 3 });
        let two = json!({ "a": 2, "m": 3, "z": 1 });
        assert_eq!(to_canonical_string(&one), to_canonical_string(&two));
    }

    #[test]
    fn nested_objects_are_sorted_recursively() {
        let value = json!({
            "outer": { "y": 1, "x": 2 },
            "list": [ { "b": 1, "a": 2 } ]
        });
        assert_eq!(
            to_canonical_string(&value),
            r#"{"list":[{"a":2,"b":1}],"outer":{"x":2,"y":1}}"#
        );
    }

    #[test]
    fn no_insignificant_whitespace() {
        let value = json!({ "a": [1, 2, 3], "b": { "c": "d" } });
        let s = to_canonical_string(&value);
        assert!(!s.contains(' '));
        assert!(!s.contains('\n'));
    }

    #[test]
    fn arrays_preserve_order() {
        let value = json!([3, 1, 2]);
        assert_eq!(to_canonical_string(&value), "[3,1,2]");
    }

    #[test]
    fn strings_are_escaped() {
        let value = json!({ "msg": "line1\nline2\t\"q\"" });
        assert_eq!(
            to_canonical_string(&value),
            r#"{"msg":"line1\nline2\t\"q\""}"#
        );
    }

    #[test]
    fn scalars_round_trip() {
        assert_eq!(to_canonical_string(&json!(null)), "null");
        assert_eq!(to_canonical_string(&json!(true)), "true");
        assert_eq!(to_canonical_string(&json!(false)), "false");
        assert_eq!(to_canonical_string(&json!(42)), "42");
        assert_eq!(to_canonical_string(&json!(-7)), "-7");
        assert_eq!(to_canonical_string(&json!("hi")), r#""hi""#);
    }

    #[test]
    fn bytes_match_string_utf8() {
        let value = json!({ "k": "v" });
        assert_eq!(
            to_canonical_bytes(&value),
            to_canonical_string(&value).into_bytes()
        );
    }
}
