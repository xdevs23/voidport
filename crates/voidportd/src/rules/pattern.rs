//! The glob is a separate syntax, never a path spelling: a rule path component
//! containing `*` is a literal name.
//!
//! * `*` matches any run of bytes, including the empty run, so `project-*`
//!   covers a child named exactly `project-`.
//! * A `*` at the start of a match does not cover a name beginning with `.`, so
//!   an un-hidden family never exposes `.git`, `.ssh` or `.env`. Only a match
//!   whose first byte is a literal `.` covers dotfiles.
//! * `?`, `[` and every other byte are literal bytes. There is no character
//!   class, no escape and no recursive `**`.
//! * A match of only `*`s is refused: that is the job of the bare-`*` wildcard
//!   rule, and two spellings of match-everything at one level would be the
//!   ambiguity the overlap rule exists to prevent.
//!
//! Comparing literal runs cannot decide an overlap: `ab*` and `*ba` share no
//! run order yet both cover `aba`. [`Pattern::overlaps`] runs a product
//! construction over the automata of the two patterns, with the leading-dot
//! rule encoded inside the automata, because a checker that ignores it wrongly
//! refuses `*x` beside `.x*`.

use std::fmt;

use super::glob::covers_bytes;
use super::name::Name;

const STAR: u8 = b'*';

const DOT: u8 = b'.';

/// Stored as the operator wrote it, because the state file contains that form and
/// error messages name it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pattern(String);

impl Pattern {
    /// # Errors
    ///
    /// Returns [`PatternError`] for an empty match, a match of only `*`s, and a
    /// match carrying a `/` or a NUL.
    pub fn parse(raw: &str) -> Result<Self, PatternError> {
        if raw.is_empty() {
            return Err(PatternError::Empty);
        }
        if raw.bytes().all(|byte| byte == STAR) {
            return Err(PatternError::MatchesEverything);
        }
        if raw.contains('/') {
            return Err(PatternError::Separator);
        }
        if raw.contains('\0') {
            return Err(PatternError::Nul);
        }
        Ok(Self(raw.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn covers(&self, name: &Name) -> bool {
        covers_bytes(self.0.as_bytes(), name.as_bytes())
    }

    /// Reachability of an accepting pair over the product of the two automata
    /// decides it. The empty string is not a witness, because a host name is
    /// never empty.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        let (left, right) = (self.0.as_bytes(), other.0.as_bytes());
        let width = right.len() + 1;
        let mut seen = vec![false; (left.len() + 1) * width];
        let mut frontier: Vec<(usize, usize)> = Vec::new();
        let discover = |frontier: &mut Vec<(usize, usize)>, seen: &mut Vec<bool>, pair| {
            let (row, column): (usize, usize) = pair;
            if !std::mem::replace(&mut seen[row * width + column], true) {
                frontier.push(pair);
            }
        };
        // The first byte is the one the leading-dot rule governs.
        for pair in successors(left, right, (0, 0), true) {
            discover(&mut frontier, &mut seen, pair);
        }
        while let Some(pair) = frontier.pop() {
            if accepts(left, pair.0) && accepts(right, pair.1) {
                return true;
            }
            for successor in successors(left, right, pair, false) {
                discover(&mut frontier, &mut seen, successor);
            }
        }
        false
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn closure(pattern: &[u8], position: usize) -> std::ops::RangeInclusive<usize> {
    let mut end = position;
    while end < pattern.len() && pattern[end] == STAR {
        end += 1;
    }
    position..=end
}

fn accepts(pattern: &[u8], position: usize) -> bool {
    *closure(pattern, position).end() == pattern.len()
}

/// Where consuming `byte` at `position` leads, or `None` if it cannot.
///
/// `start` marks the first byte of the name: only a match whose own first byte
/// is a literal `.` may consume a leading `.`.
fn step(pattern: &[u8], position: usize, byte: u8, start: bool) -> Option<usize> {
    if position >= pattern.len() {
        return None;
    }
    if start && byte == DOT {
        return (position == 0 && pattern[0] == DOT).then_some(1);
    }
    match pattern[position] {
        STAR => Some(position),
        literal if literal == byte => Some(position + 1),
        _ => None,
    }
}

/// Every pair of positions reachable without consuming anything.
fn product(
    left: &[u8],
    right: &[u8],
    at_left: usize,
    at_right: usize,
) -> impl Iterator<Item = (usize, usize)> {
    closure(left, at_left).flat_map(move |a| closure(right, at_right).map(move |b| (a, b)))
}

/// Where one side is a `*` and the other a literal, the literal fixes the byte.
/// Where both are `*`, every byte allowed by the dot rule leads to the same pair.
fn successors(
    left: &[u8],
    right: &[u8],
    pair: (usize, usize),
    start: bool,
) -> impl Iterator<Item = (usize, usize)> {
    let mut reached = Vec::new();
    for (a, b) in product(left, right, pair.0, pair.1) {
        if a == left.len() || b == right.len() {
            continue;
        }
        let stepped = if left[a] == STAR && right[b] == STAR {
            Some((a, b))
        } else {
            let byte = if left[a] == STAR { right[b] } else { left[a] };
            step(left, a, byte, start).zip(step(right, b, byte, start))
        };
        if let Some((a, b)) = stepped {
            reached.extend(product(left, right, a, b));
        }
    }
    reached.into_iter()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PatternError {
    #[error("a match must not be empty")]
    Empty,
    #[error(
        "a match of only `*` covers every name, which is the `*` rule's job; \
         write a `*` rule on the directory instead"
    )]
    MatchesEverything,
    #[error("a match covers one child name, so it must not contain a `/` separator")]
    Separator,
    #[error("a match must not contain a NUL byte")]
    Nul,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(raw: &str) -> Pattern {
        Pattern::parse(raw).expect("valid match")
    }

    fn covers(raw: &str, name: &str) -> bool {
        pattern(raw).covers(&Name::new(name).expect("valid name"))
    }

    #[test]
    fn names_are_bytes_and_never_forced_through_utf8() {
        let raw = Name::new(vec![0xff, 0xfe, b'-', b's', b'r', b'c']).expect("valid name");
        assert!(pattern("*-src").covers(&raw));
        assert!(!pattern("*-doc").covers(&raw));
        let unicode = Name::new("café-1").expect("valid name");
        assert!(pattern("café-*").covers(&unicode));
    }

    #[test]
    fn a_leading_star_never_covers_a_dotfile() {
        assert!(!covers("*-a", ".b-a"), "the shell's own rule");
        assert!(!covers("*x", ".x"));
        assert!(!covers("*git", ".git"));
        assert!(covers(".x*", ".xyz"));
        assert!(covers(".x*", ".x"));
        assert!(covers(".*", ".git"));
        assert!(!covers(".*", "git"));
        // A `.` reached by skipping a leading `*` is not "the first byte".
        assert!(!covers("*.x", ".x"));
        assert!(covers("*.x", "a.x"));
        assert!(covers("a*", "a.b"));
    }

    #[test]
    fn a_match_is_refused_when_it_can_cover_nothing_or_everything() {
        assert_eq!(Pattern::parse(""), Err(PatternError::Empty));
        assert_eq!(Pattern::parse("*"), Err(PatternError::MatchesEverything));
        assert_eq!(Pattern::parse("***"), Err(PatternError::MatchesEverything));
        assert_eq!(Pattern::parse("a/b"), Err(PatternError::Separator));
        assert_eq!(Pattern::parse("a\0b"), Err(PatternError::Nul));
        assert_eq!(pattern("a*").as_str(), "a*");
        assert_eq!(pattern("a*").to_string(), "a*");
    }

    #[test]
    fn overlap_is_decided_by_the_product_construction() {
        let overlapping = [
            ("ab*", "*ba"),
            ("a*b*c", "*d*"),
            ("project-*", "*-src"),
            ("a*", "*a"),
            ("abc", "a*c"),
            ("x*", "*y*"),
        ];
        for (left, right) in overlapping {
            let (left, right) = (pattern(left), pattern(right));
            assert!(
                left.overlaps(&right) && right.overlaps(&left),
                "{left} and {right} share a name"
            );
        }

        let disjoint = [
            ("a*b", "b*a"),
            ("proj-*", "project-*"),
            // Disjoint only because of the leading-dot rule: a name both cover
            // would have to start with `.` and be matched by a leading `*`.
            ("*x", ".x*"),
            ("a*", "b*"),
            ("*-src", "*-doc"),
            ("abc", "abd"),
        ];
        for (left, right) in disjoint {
            let (left, right) = (pattern(left), pattern(right));
            assert!(
                !left.overlaps(&right) && !right.overlaps(&left),
                "{left} and {right} cover no common name"
            );
        }
    }

    #[test]
    fn a_pattern_always_overlaps_itself() {
        for raw in ["a*", "*a", "a*b*c", ".x*", "plain"] {
            let one = pattern(raw);
            assert!(one.overlaps(&one), "{one} covers its own names");
        }
    }

    #[test]
    fn the_pinned_witnesses_are_covered_by_both_patterns() {
        assert!(covers("ab*", "aba") && covers("*ba", "aba"));
        assert!(covers("a*b*c", "abdc") && covers("*d*", "abdc"));
        for name in ["ab", "ba", "aba", "bab", "ab-ba", "x", ".x", ".xx", "xx"] {
            assert!(
                !(covers("a*b", name) && covers("b*a", name)),
                "{name} is covered by both a*b and b*a"
            );
            assert!(
                !(covers("*x", name) && covers(".x*", name)),
                "{name} is covered by both *x and .x*"
            );
        }
    }

    fn words(alphabet: &[u8], maximum: usize) -> Vec<Vec<u8>> {
        let mut all = vec![Vec::new()];
        let mut level = vec![Vec::new()];
        for _ in 0..maximum {
            level = level
                .iter()
                .flat_map(|prefix| {
                    alphabet.iter().map(move |byte| {
                        let mut word = prefix.clone();
                        word.push(*byte);
                        word
                    })
                })
                .collect();
            all.extend(level.iter().cloned());
        }
        all
    }

    fn automaton_covers(pattern: &[u8], name: &[u8]) -> bool {
        let mut positions: Vec<_> = closure(pattern, 0).collect();
        for (index, byte) in name.iter().enumerate() {
            positions = positions
                .into_iter()
                .filter_map(|position| step(pattern, position, *byte, index == 0))
                .flat_map(|position| closure(pattern, position))
                .collect();
            positions.sort_unstable();
            positions.dedup();
        }
        positions.contains(&pattern.len())
    }

    #[test]
    fn literal_run_membership_agrees_with_the_automaton_exhaustively() {
        let names = words(b"ab.", 5);
        // Include empty inputs and catch-all globs without the restrictions of
        // the child-pattern parser. Repeated stars and dots occur at every
        // position.
        for raw in words(b"ab.*", 5) {
            for name in &names {
                assert_eq!(
                    covers_bytes(&raw, name),
                    automaton_covers(&raw, name),
                    "pattern {raw:?}, name {name:?}"
                );
            }
        }
    }

    #[test]
    fn the_overlap_checker_agrees_with_exhaustive_enumeration() {
        let alphabet = *b"ab.";
        let patterns = [
            "a*", "*a", "ab*", "*ba", "a*b", "b*a", ".a*", "*a.", "a*b*a", "*.*", "ab", ".a",
        ];
        let mut names: Vec<Vec<u8>> = Vec::new();
        for length in 1..=5usize {
            let mut word = vec![0usize; length];
            loop {
                names.push(word.iter().map(|index| alphabet[*index]).collect());
                let mut position = 0;
                while position < length {
                    word[position] += 1;
                    if word[position] < alphabet.len() {
                        break;
                    }
                    word[position] = 0;
                    position += 1;
                }
                if position == length {
                    break;
                }
            }
        }
        for left in patterns {
            for right in patterns {
                let (left, right) = (pattern(left), pattern(right));
                let witness = names.iter().any(|raw| {
                    Name::new(raw).is_ok_and(|name| left.covers(&name) && right.covers(&name))
                });
                assert_eq!(
                    left.overlaps(&right),
                    witness,
                    "{left} vs {right}: the product construction and the \
                     enumeration disagree"
                );
            }
        }
    }
}
