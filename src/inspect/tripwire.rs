//! Honeytoken detection for `agent-tripwire` planted values.
//!
//! A planted value contains the literal marker `TRIPWIRE` followed by an eight
//! character base32 id whose last two characters are a checksum over the first
//! six. The checksum is what makes a match unambiguous: the word "tripwire" on
//! its own is not a finding, but a well formed id is.
//!
//! The format is reimplemented here rather than depended on, because
//! `agent-tripwire` is not published as a library crate. The two
//! implementations are interchangeable; see `agent-tripwire`'s `src/token.rs`.

use sha2::{Digest, Sha256};

/// The literal marker inside every planted value.
pub const MARKER: &str = "TRIPWIRE";
/// The length of a tripwire id, in characters.
pub const ID_LEN: usize = 8;
/// The number of random characters in an id; the rest is a checksum.
const RANDOM_LEN: usize = 6;
/// The base32 alphabet used for ids.
const BASE32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// A honeytoken found in some text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    /// The id of the planted value.
    pub id: String,
    /// Where the marker starts, in bytes.
    pub start: usize,
    /// Where the marker and id end, in bytes.
    pub end: usize,
    /// Where the whole planted value ends, in bytes, including any trailing
    /// secret material that belongs to the same credential.
    pub value_end: usize,
}

/// Finds every honeytoken in `text`.
pub fn scan(text: &str) -> Vec<Hit> {
    let bytes = text.as_bytes();
    let marker = MARKER.as_bytes();
    let len = marker.len() + ID_LEN;
    let mut hits = Vec::new();
    let mut i = 0;

    while i + len <= bytes.len() {
        if bytes[i..i + marker.len()].eq_ignore_ascii_case(marker) {
            let id: String = bytes[i + marker.len()..i + len]
                .iter()
                .map(|b| b.to_ascii_uppercase() as char)
                .collect();
            if id.bytes().all(|b| BASE32.contains(&b)) && is_valid_id(&id) {
                let mut value_end = i + len;
                // The random tail of a planted value is secret material too.
                while value_end < bytes.len()
                    && (bytes[value_end].is_ascii_alphanumeric()
                        || b"+/".contains(&bytes[value_end]))
                {
                    value_end += 1;
                }
                hits.push(Hit {
                    id,
                    start: i,
                    end: i + len,
                    value_end,
                });
                i += len;
                continue;
            }
        }
        i += 1;
    }

    hits
}

/// True when `id` is eight base32 characters with a valid checksum.
pub fn is_valid_id(id: &str) -> bool {
    id.len() == ID_LEN
        && id.bytes().all(|b| BASE32.contains(&b))
        && id[RANDOM_LEN..] == check_chars(&id[..RANDOM_LEN])
}

/// The two checksum characters for a random part.
fn check_chars(random: &str) -> String {
    let digest = Sha256::new()
        .chain_update(b"agent-tripwire:")
        .chain_update(random.as_bytes())
        .finalize();
    let bits = (u16::from(digest[0]) << 2) | u16::from(digest[1] >> 6);
    [bits >> 5, bits & 0x1f]
        .iter()
        .map(|&i| BASE32[usize::from(i)] as char)
        .collect()
}

/// Builds an id with a valid checksum from a random part.
///
/// Used by the tests to produce values the scanner must recognise.
pub fn id_for_testing(random: &str) -> String {
    format!("{random}{}", check_chars(random))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_a_well_formed_honeytoken() {
        let id = id_for_testing("ABC234");
        let text = format!("AWS_ACCESS_KEY_ID=AKIA{MARKER}{id}EXTRATAILVALUE");
        let hits = scan(&text);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, id);
    }

    #[test]
    fn the_marker_alone_is_not_a_honeytoken() {
        assert!(scan("this mentions TRIPWIRE in passing").is_empty());
        assert!(scan("TRIPWIRE").is_empty());
    }

    #[test]
    fn a_corrupted_checksum_is_not_a_honeytoken() {
        let id = id_for_testing("ABC234");
        let mut broken: Vec<char> = id.chars().collect();
        let last = broken.len() - 1;
        broken[last] = if broken[last] == 'A' { 'B' } else { 'A' };
        let broken: String = broken.into_iter().collect();
        assert!(scan(&format!("value TRIPWIRE{broken}")).is_empty());
    }

    #[test]
    fn the_marker_is_matched_case_insensitively() {
        let id = id_for_testing("ABC234");
        let hits = scan(&format!("tripwire{id}"));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, id);
    }

    #[test]
    fn the_span_covers_the_trailing_secret_material() {
        let id = id_for_testing("ABC234");
        let text = format!("AKIA{MARKER}{id}SECRETTAIL");
        let hits = scan(&text);
        assert_eq!(hits[0].value_end, text.len());
    }

    #[test]
    fn most_random_words_fail_the_checksum() {
        // The checksum is ten bits, so roughly one word in 1024 passes. The
        // sequence is fixed so the test stays deterministic.
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut valid = 0;
        let mut total = 0;
        for &a in alphabet {
            for &b in alphabet {
                for &c in alphabet {
                    let random: String =
                        [a, b, c, a, b, c].iter().map(|&x| char::from(x)).collect();
                    let candidate = format!("{random}AA");
                    total += 1;
                    if is_valid_id(&candidate) {
                        valid += 1;
                    }
                }
            }
        }
        assert!(valid < total / 100, "{valid} of {total} passed");
    }
}
