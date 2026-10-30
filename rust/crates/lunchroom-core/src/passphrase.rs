//! The passphrase check behind the user's confirmation (spec §7 A1.3).
//!
//! A passphrase is kept only as a verifier line, `pbkdf2-sha256$<iterations>$<salt hex>$<hash hex>`:
//! PBKDF2 (RFC 8018) over HMAC-SHA-256 (RFC 2104), built on `sha2` alone. The line is read from a
//! file only root can write; a process of the user's own cannot make one that passes.

use sha2::{Digest, Sha256};

/// PBKDF2 iterations a new verifier uses, and the fewest a verifier may name.
pub const ITERATIONS: u32 = 600_000;
/// The scheme a verifier line names.
pub const SCHEME: &str = "pbkdf2-sha256";
/// Bytes of salt.
pub const SALT_BYTES: usize = 16;
/// Bytes of derived key.
pub const HASH_BYTES: usize = 32;
/// The fewest characters a new passphrase has.
pub const MIN_LENGTH: usize = 12;

/// HMAC-SHA-256 block size, in bytes (RFC 2104).
const BLOCK: usize = 64;

/// HMAC-SHA-256 under one key, with the two padded-key hash states ready to copy.
#[derive(Clone)]
struct Hmac {
    inner: Sha256,
    outer: Sha256,
}

impl Hmac {
    fn new(key: &[u8]) -> Self {
        let mut block = [0u8; BLOCK];
        if key.len() > BLOCK {
            block[..HASH_BYTES].copy_from_slice(Sha256::digest(key).as_slice());
        } else {
            block[..key.len()].copy_from_slice(key);
        }
        let mut inner = Sha256::new();
        inner.update(block.map(|b| b ^ 0x36));
        let mut outer = Sha256::new();
        outer.update(block.map(|b| b ^ 0x5c));
        Self { inner, outer }
    }

    /// The MAC of `parts` taken as one message.
    fn mac(&self, parts: &[&[u8]]) -> [u8; HASH_BYTES] {
        let mut inner = self.inner.clone();
        for part in parts {
            inner.update(part);
        }
        let mut outer = self.outer.clone();
        outer.update(inner.finalize().as_slice());
        let mut out = [0u8; HASH_BYTES];
        out.copy_from_slice(outer.finalize().as_slice());
        out
    }
}

/// PBKDF2-HMAC-SHA-256 (RFC 8018 §5.2): `length` bytes derived from `password` and `salt` in
/// `iterations` rounds.
#[must_use]
pub fn pbkdf2(password: &[u8], salt: &[u8], iterations: u32, length: usize) -> Vec<u8> {
    let prf = Hmac::new(password);
    let mut derived = Vec::with_capacity(length);
    let mut index: u32 = 1;
    while derived.len() < length {
        let mut last = prf.mac(&[salt, index.to_be_bytes().as_slice()]);
        let mut block = last;
        for _ in 1..iterations {
            last = prf.mac(&[last.as_slice()]);
            for (b, l) in block.iter_mut().zip(last) {
                *b ^= l;
            }
        }
        let take = (length - derived.len()).min(HASH_BYTES);
        derived.extend_from_slice(&block[..take]);
        index += 1;
    }
    derived
}

/// Whether `a` and `b` are equal, reading all of both when they are the same length.
#[must_use]
pub fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// `bytes` as lower-case hexadecimal.
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

/// The bytes `text` spells in lower-case hexadecimal; `None` for any other text.
fn from_hex(text: &str) -> Option<Vec<u8>> {
    let digits = text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if !digits || !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|k| u8::from_str_radix(&text[k..k + 2], 16).ok())
        .collect()
}

/// A passphrase's verifier: what a typed passphrase is checked against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verifier {
    iterations: u32,
    salt: [u8; SALT_BYTES],
    hash: [u8; HASH_BYTES],
}

impl Verifier {
    /// The verifier of `secret` under `salt`, in `iterations` rounds.
    #[must_use]
    pub fn new(secret: &str, salt: [u8; SALT_BYTES], iterations: u32) -> Self {
        let mut hash = [0u8; HASH_BYTES];
        hash.copy_from_slice(&pbkdf2(secret.as_bytes(), &salt, iterations, HASH_BYTES));
        Self {
            iterations,
            salt,
            hash,
        }
    }

    /// The verifier a line holds: one line, the scheme, a decimal iteration count of at least
    /// `min_iterations`, the salt and the hash in lower-case hexadecimal. A trailing newline is
    /// allowed.
    ///
    /// # Errors
    /// What is wrong with the line.
    pub fn parse(line: &str, min_iterations: u32) -> Result<Self, String> {
        let line = line.strip_suffix('\n').unwrap_or(line);
        let parts: Vec<&str> = line.split('$').collect();
        let [scheme, iterations, salt, hash] = parts.as_slice() else {
            return Err("it is not four fields joined by $".to_owned());
        };
        if *scheme != SCHEME {
            return Err(format!("its scheme is not {SCHEME}"));
        }
        let digits = !iterations.is_empty()
            && iterations.bytes().all(|b| b.is_ascii_digit())
            && !iterations.starts_with('0');
        let iterations: u32 = iterations
            .parse()
            .ok()
            .filter(|_| digits)
            .ok_or_else(|| "its iteration count is not a number".to_owned())?;
        if iterations < min_iterations {
            return Err(format!(
                "its iteration count {iterations} is below {min_iterations}"
            ));
        }
        let salt = from_hex(salt)
            .and_then(|b| <[u8; SALT_BYTES]>::try_from(b).ok())
            .ok_or_else(|| format!("its salt is not {} hexadecimal digits", SALT_BYTES * 2))?;
        let hash = from_hex(hash)
            .and_then(|b| <[u8; HASH_BYTES]>::try_from(b).ok())
            .ok_or_else(|| format!("its hash is not {} hexadecimal digits", HASH_BYTES * 2))?;
        Ok(Self {
            iterations,
            salt,
            hash,
        })
    }

    /// The verifier as its line, without a newline.
    #[must_use]
    pub fn line(&self) -> String {
        format!(
            "{SCHEME}${}${}${}",
            self.iterations,
            to_hex(&self.salt),
            to_hex(&self.hash)
        )
    }

    /// Whether `secret` is the passphrase this verifier was made from.
    #[must_use]
    pub fn matches(&self, secret: &str) -> bool {
        let derived = pbkdf2(secret.as_bytes(), &self.salt, self.iterations, HASH_BYTES);
        same(&derived, &self.hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8018 §5.2 with HMAC-SHA-256 (the published vectors): one block, one to 4096 rounds, and
    // a key of two blocks.
    #[test]
    fn pbkdf2_matches_the_published_vectors() {
        let vectors: [(&str, &str, u32, usize, &str); 4] = [
            (
                "password",
                "salt",
                1,
                32,
                "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
            ),
            (
                "password",
                "salt",
                2,
                32,
                "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
            ),
            (
                "password",
                "salt",
                4096,
                32,
                "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
            ),
            (
                "passwordPASSWORDpassword",
                "saltSALTsaltSALTsaltSALTsaltSALTsalt",
                4096,
                40,
                "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9",
            ),
        ];
        for (password, salt, rounds, length, expected) in vectors {
            let derived = pbkdf2(password.as_bytes(), salt.as_bytes(), rounds, length);
            assert_eq!(to_hex(&derived), expected, "{password} {rounds}");
        }
    }

    // RFC 2104: a key longer than the block is hashed first, so a 65-byte key and the hash of it
    // as a key give the same MAC; a 64-byte key is used as it is.
    #[test]
    fn hmac_hashes_a_key_longer_than_the_block() {
        let long = [b'k'; 65];
        let hashed = Sha256::digest(long);
        let a = Hmac::new(&long).mac(&[b"message"]);
        let b = Hmac::new(hashed.as_slice()).mac(&[b"message"]);
        assert_eq!(a, b);
        let exact = Hmac::new(&[b'k'; 64]).mac(&[b"message"]);
        assert_ne!(exact, a);
        // The parts are one message.
        assert_eq!(
            Hmac::new(b"key").mac(&[b"mess", b"age"]),
            Hmac::new(b"key").mac(&[b"message"])
        );
    }

    // The derived key is compared in full, by length and by every byte.
    #[test]
    fn comparison_sees_every_byte_and_the_length() {
        assert!(same(b"abc", b"abc"));
        assert!(same(b"", b""));
        assert!(!same(b"abc", b"abd"));
        assert!(!same(b"abc", b"bbc"));
        assert!(!same(b"abc", b"ab"));
        assert!(!same(b"", b"a"));
    }

    // A verifier is written as its line and read back the same; the right passphrase matches it
    // and any other does not.
    #[test]
    fn a_verifier_round_trips_and_matches_only_its_passphrase() {
        let v = Verifier::new("correct horse battery", [9; SALT_BYTES], 3);
        let line = v.line();
        assert!(line.starts_with("pbkdf2-sha256$3$09090909090909090909090909090909$"));
        assert_eq!(line.len(), "pbkdf2-sha256$3$".len() + 32 + 1 + 64);
        assert_eq!(Verifier::parse(&line, 3), Ok(v.clone()));
        assert_eq!(Verifier::parse(&format!("{line}\n"), 3), Ok(v.clone()));
        assert!(v.matches("correct horse battery"));
        for wrong in ["", "correct horse batter", "Correct horse battery", "x"] {
            assert!(!v.matches(wrong), "{wrong:?}");
        }
        assert_ne!(
            v.line(),
            Verifier::new("correct horse battery", [8; SALT_BYTES], 3).line()
        );
    }

    // A line that is not exactly the format, or names fewer iterations than the least allowed, is
    // not a verifier.
    #[test]
    fn a_malformed_line_or_too_few_iterations_is_rejected() {
        // A salt with letters in it, so that upper case is a different spelling.
        let good = Verifier::new("correct horse battery", [0xab; SALT_BYTES], 1);
        let hash = to_hex(&good.hash);
        let salt = to_hex(&good.salt);
        let line = format!("pbkdf2-sha256$600000${salt}${hash}");
        assert!(Verifier::parse(&line, ITERATIONS).is_ok());
        assert!(Verifier::parse(&line, ITERATIONS + 1).is_err());
        let cases = [
            String::new(),
            "pbkdf2-sha256".to_owned(),
            format!("pbkdf2-sha256$600000${salt}"),
            format!("pbkdf2-sha256$600000${salt}${hash}$x"),
            format!("pbkdf2-sha1$600000${salt}${hash}"),
            format!("PBKDF2-SHA256$600000${salt}${hash}"),
            format!("pbkdf2-sha256$599999${salt}${hash}"),
            format!("pbkdf2-sha256$0${salt}${hash}"),
            format!("pbkdf2-sha256$${salt}${hash}"),
            format!("pbkdf2-sha256$+600000${salt}${hash}"),
            format!("pbkdf2-sha256$0600000${salt}${hash}"),
            format!("pbkdf2-sha256$600000.0${salt}${hash}"),
            format!("pbkdf2-sha256$99999999999${salt}${hash}"),
            format!("pbkdf2-sha256$600000${}${hash}", &salt[2..]),
            format!("pbkdf2-sha256$600000${salt}00${hash}"),
            format!("pbkdf2-sha256$600000${}${hash}", salt.to_uppercase()),
            format!("pbkdf2-sha256$600000${}g${hash}", &salt[1..]),
            format!("pbkdf2-sha256$600000${salt}${}", &hash[2..]),
            format!("pbkdf2-sha256$600000${salt}${hash}00"),
            format!("pbkdf2-sha256$600000${salt}${hash}\nsecond line"),
            format!(" pbkdf2-sha256$600000${salt}${hash}"),
        ];
        for line in cases {
            assert!(Verifier::parse(&line, ITERATIONS).is_err(), "{line:?}");
        }
    }
}
