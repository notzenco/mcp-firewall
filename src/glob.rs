//! Glob matching for path-style policy rules.
//!
//! The glob dialect is deliberately small, because it is part of a security
//! decision and an ambiguous match is an ambiguous policy:
//!
//! * `*` matches any run of characters except `/`;
//! * `**` matches any run of characters, including `/`;
//! * `?` matches exactly one character except `/`;
//! * `[abc]`, `[a-z]` and `[!abc]` match one character from the set;
//! * every other character is literal.
//!
//! A `**` that is followed by a `/` matches zero or more whole path segments,
//! so `a/**/b` matches `a/b` as well as `a/x/y/b`.

use regex::Regex;

/// A glob that failed to compile.
#[derive(Debug, thiserror::Error)]
pub enum GlobError {
    #[error("invalid glob `{pattern}`: {source}")]
    Invalid {
        pattern: String,
        #[source]
        source: regex::Error,
    },
}

/// A compiled glob pattern.
#[derive(Debug, Clone)]
pub struct Glob {
    pattern: String,
    regex: Regex,
}

impl Glob {
    /// Compiles `pattern` into a matcher.
    pub fn new(pattern: &str) -> Result<Self, GlobError> {
        let regex = Regex::new(&translate(pattern)).map_err(|source| GlobError::Invalid {
            pattern: pattern.to_string(),
            source,
        })?;
        Ok(Self {
            pattern: pattern.to_string(),
            regex,
        })
    }

    /// True when `value` matches the whole pattern.
    pub fn matches(&self, value: &str) -> bool {
        self.regex.is_match(value)
    }

    /// The pattern this glob was compiled from.
    pub fn pattern(&self) -> &str {
        &self.pattern
    }
}

/// Compiles a list of globs, failing if any of them is invalid.
pub fn compile_all(patterns: &[String]) -> Result<Vec<Glob>, GlobError> {
    patterns.iter().map(|p| Glob::new(p)).collect()
}

/// True when `value` matches at least one of `patterns`.
pub fn any_match(patterns: &[Glob], value: &str) -> bool {
    patterns.iter().any(|g| g.matches(value))
}

/// True when `value` matches none of `patterns`.
pub fn none_match(patterns: &[Glob], value: &str) -> bool {
    !any_match(patterns, value)
}

/// Translates a glob into an anchored regular expression.
fn translate(pattern: &str) -> String {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::from("^");
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            '*' => {
                let double = i + 1 < chars.len() && chars[i + 1] == '*';
                if double {
                    i += 2;
                    if i < chars.len() && chars[i] == '/' {
                        out.push_str("(?:.*/)?");
                        i += 1;
                    } else {
                        out.push_str(".*");
                    }
                } else {
                    out.push_str("[^/]*");
                    i += 1;
                }
            }
            '?' => {
                out.push_str("[^/]");
                i += 1;
            }
            '[' => match char_class(&chars, i) {
                Some((class, next)) => {
                    out.push_str(&class);
                    i = next;
                }
                None => {
                    out.push_str(&regex::escape("["));
                    i += 1;
                }
            },
            c => {
                out.push_str(&regex::escape(&c.to_string()));
                i += 1;
            }
        }
    }

    out.push('$');
    out
}

/// Builds a character class from the `[` at `start`, if it is closed.
fn char_class(chars: &[char], start: usize) -> Option<(String, usize)> {
    let mut i = start + 1;
    let mut negated = false;
    if i < chars.len() && (chars[i] == '!' || chars[i] == '^') {
        negated = true;
        i += 1;
    }

    let mut body = String::new();
    let mut closed = false;
    // A `]` immediately after the opening bracket is a literal.
    if i < chars.len() && chars[i] == ']' {
        body.push_str("\\]");
        i += 1;
    }

    while i < chars.len() {
        match chars[i] {
            ']' => {
                closed = true;
                i += 1;
                break;
            }
            '\\' => {
                body.push_str("\\\\");
                i += 1;
            }
            c => {
                body.push(c);
                i += 1;
            }
        }
    }

    if !closed || body.is_empty() {
        return None;
    }

    let prefix = if negated { "^" } else { "" };
    Some((format!("[{prefix}{body}]"), i))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(pattern: &str, value: &str) -> bool {
        Glob::new(pattern).expect("glob compiles").matches(value)
    }

    #[test]
    fn star_does_not_cross_a_slash() {
        assert!(m("*.txt", "notes.txt"));
        assert!(!m("*.txt", "dir/notes.txt"));
        assert!(!m("/a/*", "/a/b/c"));
    }

    #[test]
    fn double_star_crosses_slashes() {
        assert!(m("/a/**", "/a/b/c"));
        assert!(m("/a/**", "/a/"));
        assert!(!m("/a/**", "/b/c"));
    }

    #[test]
    fn double_star_matches_zero_segments() {
        assert!(m("a/**/b", "a/b"));
        assert!(m("a/**/b", "a/x/b"));
        assert!(m("a/**/b", "a/x/y/b"));
        assert!(!m("a/**/b", "a/x/y"));
    }

    #[test]
    fn question_mark_matches_exactly_one_character() {
        assert!(m("a?c", "abc"));
        assert!(!m("a?c", "ac"));
        assert!(!m("a?c", "a/c"));
    }

    #[test]
    fn character_classes_match_one_character() {
        assert!(m("a[bc]d", "abd"));
        assert!(m("a[bc]d", "acd"));
        assert!(!m("a[bc]d", "aed"));
        assert!(m("a[b-d]e", "ace"));
        assert!(m("a[!bc]d", "aed"));
        assert!(!m("a[!bc]d", "abd"));
    }

    #[test]
    fn unclosed_bracket_is_literal() {
        assert!(m("a[b", "a[b"));
    }

    #[test]
    fn dots_are_literal() {
        assert!(m("a.b", "a.b"));
        assert!(!m("a.b", "axb"));
    }

    #[test]
    fn whole_value_must_match() {
        assert!(!m("abc", "abcd"));
        assert!(!m("abc", "xabc"));
    }

    #[test]
    fn compiles_all_and_matches_any() {
        let globs = compile_all(&["/a/**".to_string(), "/b/**".to_string()]).unwrap();
        assert!(any_match(&globs, "/a/x"));
        assert!(any_match(&globs, "/b/x"));
        assert!(none_match(&globs, "/c/x"));
    }

    #[test]
    fn regex_metacharacters_are_literal() {
        // Every literal is escaped, so a glob can never fail to compile and
        // can never accidentally mean something else.
        assert!(m("a(", "a("));
        assert!(!m("a(", "ab"));
        assert!(m("a.b+c", "a.b+c"));
    }
}
