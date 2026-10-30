//! The JSON Canonicalization Scheme (RFC 8785) and the SHA-256 that an approval binds to.
//!
//! Spec: §8 A2.1 (an approval covers the call's exact input: SHA-256 of the input serialised by
//! RFC 8785). Numbers are IEEE 754 doubles written the way ECMAScript writes them, strings are
//! escaped the way ECMAScript's `JSON.stringify` escapes them, and object members are sorted by
//! their names' UTF-16 code units. The tests compare against vectors that Node's own
//! `JSON.stringify` produced (`rust/tools/gen_jcs_vectors.mjs`).

use std::fmt::Write as _;

use serde_json::Value;
use sha2::{Digest, Sha256};

/// `value` in RFC 8785 canonical form.
#[must_use]
pub fn canonical(value: &Value) -> String {
    let mut out = String::new();
    write_value(value, &mut out);
    out
}

/// `value`'s canonical form as the user is shown it (A2.2): characters a terminal would act on or
/// that reorder text (C1 controls, DEL, bidirectional overrides and isolates, line and paragraph
/// separators) are written as `\u{XXXX}`, so what the user reads is the call that runs. The hash
/// is of the canonical form itself.
#[must_use]
pub fn shown(value: &Value) -> String {
    canonical(value)
        .chars()
        .map(|c| {
            if matches!(c, '\u{7f}'..='\u{9f}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
                format!("\\u{{{:04x}}}", u32::from(c))
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// SHA-256 of `value`'s canonical form, in lower-case hex (A2.1).
#[must_use]
pub fn input_hash(value: &Value) -> String {
    let digest = Sha256::digest(canonical(value).as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

fn write_value(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&number(n.as_f64().unwrap_or(f64::NAN))),
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (k, item) in items.iter().enumerate() {
                if k > 0 {
                    out.push(',');
                }
                write_value(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut members: Vec<(&String, &Value)> = map.iter().collect();
            members.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            out.push('{');
            for (k, (name, item)) in members.into_iter().enumerate() {
                if k > 0 {
                    out.push(',');
                }
                write_string(name, out);
                out.push(':');
                write_value(item, out);
            }
            out.push('}');
        }
    }
}

/// A string as ECMAScript's `JSON.stringify` writes it.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A double as ECMAScript's `Number.prototype.toString` writes it (RFC 8785 section 3.2.2.3).
/// JSON carries no NaN or infinity; were one to reach here it is written as `null`, as
/// `JSON.stringify` does.
fn number(x: f64) -> String {
    if !x.is_finite() {
        return "null".to_owned();
    }
    if x == 0.0 {
        return "0".to_owned();
    }
    if x < 0.0 {
        return format!("-{}", number(-x));
    }
    // Rust writes the shortest digits that read back as `x`: "d.ddde±x" or "de±x".
    let (digits, n) = scientific(&format!("{x:e}"));
    let digits = even_on_tie(digits, n, x);
    let k = i64::try_from(digits.len()).unwrap_or(i64::MAX);
    // x = 0.digits × 10^n
    if k <= n && n <= 21 {
        format!(
            "{digits}{}",
            "0".repeat(usize::try_from(n - k).unwrap_or(0))
        )
    } else if 0 < n && n <= 21 {
        let (int, frac) = digits.split_at(usize::try_from(n).unwrap_or(0));
        format!("{int}.{frac}")
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat(usize::try_from(-n).unwrap_or(0)))
    } else {
        let e = n - 1;
        let sign = if e < 0 { '-' } else { '+' };
        let (first, rest) = digits.split_at(1);
        if rest.is_empty() {
            format!("{first}e{sign}{}", e.unsigned_abs())
        } else {
            format!("{first}.{rest}e{sign}{}", e.unsigned_abs())
        }
    }
}

/// The significant digits of Rust's `{:e}` text, without trailing zeros, and `n` such that the
/// value is 0.digits × 10^n.
fn scientific(sci: &str) -> (String, i64) {
    let (mantissa, exp) = sci.split_once('e').unwrap_or((sci, "0"));
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let digits = digits.trim_end_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };
    (digits.to_owned(), exp.parse::<i64>().unwrap_or(0) + 1)
}

/// ECMAScript's tie rule: when two shortest digit strings are equally close to `x`, the one ending
/// in an even digit is written. Rust's shortest digits are the closest, but on an exact tie they
/// can end in the odd one; `x`'s exact decimal value then lies exactly midway between the two.
fn even_on_tie(digits: String, n: i64, x: f64) -> String {
    let Some(last) = digits.bytes().last().map(|b| b - b'0') else {
        return digits;
    };
    if last % 2 == 0 {
        return digits;
    }
    // A double's exact decimal value has at most 767 significant digits.
    let (exact, exact_n) = scientific(&format!("{x:.800e}"));
    let head = &digits[..digits.len() - 1];
    for other in [last - 1, last + 1] {
        if other > 9 || (head.is_empty() && other == 0) {
            continue;
        }
        let lower = head.to_owned() + &(last.min(other)).to_string();
        let midpoint = lower + "5";
        let candidate = format!("{head}{other}");
        let reads_back = format!("0.{candidate}e{n}").parse::<f64>() == Ok(x);
        if exact_n == n && exact == midpoint && reads_back {
            return candidate;
        }
    }
    digits
}

#[cfg(test)]
mod tests {
    use super::*;

    // A2.2: control and direction characters are shown escaped; everything else as the call has it.
    #[test]
    fn the_shown_call_escapes_what_a_terminal_would_act_on() {
        let v = serde_json::json!({"command": "rm \u{202e}txt.exe\u{9b}2J é"});
        assert_eq!(shown(&v), r#"{"command":"rm \u{202e}txt.exe\u{009b}2J é"}"#);
        // The hash binds the call itself, not the shown form.
        assert_ne!(canonical(&v), shown(&v));
    }

    #[derive(serde::Deserialize)]
    struct Vector {
        input: String,
        canonical: String,
    }

    // §8::1 (canonical input) — every vector Node's `JSON.stringify` produced: numbers
    // across magnitudes and RFC 8785's edge cases, string escapes, and member order by UTF-16.
    #[test]
    fn canonical_form_matches_ecmascript_vectors() {
        let vectors: Vec<Vector> =
            serde_json::from_str(include_str!("jcs/vectors.json")).unwrap_or_default();
        assert!(vectors.len() > 300);
        for v in &vectors {
            let value: Value = serde_json::from_str(&v.input).unwrap_or(Value::Null);
            assert_eq!(canonical(&value), v.canonical, "{}", v.input);
        }
    }

    // §8::1 — the hash ignores layout and member order, and any change of one byte of
    // the input's content changes it.
    #[test]
    fn input_hash_is_layout_free_and_byte_exact() {
        let a: Value =
            serde_json::from_str(r#"{"command":"git push","timeout":5}"#).unwrap_or(Value::Null);
        let b: Value = serde_json::from_str("{ \"timeout\" : 5.0,\n \"command\" : \"git push\" }")
            .unwrap_or(Value::Null);
        let c: Value =
            serde_json::from_str(r#"{"command":"git pusH","timeout":5}"#).unwrap_or(Value::Null);
        assert_eq!(input_hash(&a), input_hash(&b));
        assert_ne!(input_hash(&a), input_hash(&c));
        assert_eq!(input_hash(&a).len(), 64);
        // SHA-256 of the canonical text `{}`.
        assert_eq!(
            input_hash(&Value::Object(serde_json::Map::new())),
            "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );
    }
}
