//! Child-name patterns: the `match` a pattern rule carries.
//!
//! A pattern rule governs the children of one directory whose *names* a glob
//! covers — `match = "project-*"` under `path = "/a"`. The glob is its own
//! syntax and never a path spelling: a rule path component containing `*` is
//! still the literal name it has always been, so no deployed configuration
//! changes meaning and no host name becomes unnameable.
//!
//! # The language, pinned to the byte
//!
//! * `*` matches any run of **bytes, including the empty run**, so
//!   `project-*` covers a child named exactly `project-`.
//! * Names are bytes, never forced through UTF-8, and matching is byte-wise.
//! * A `*` at the **start** of a match does not cover a name beginning with
//!   `.` — the shell's own rule, chosen so an un-hidden family never
//!   accidentally exposes `.git`, `.ssh` or `.env`. Only a match whose very
//!   first byte is a literal `.` covers dotfiles.
//! * `?`, `[` and every other byte are ordinary literal bytes. There is no
//!   character class, no escape and no recursive `**`.
//! * A match consisting only of `*`s is refused: that is the bare-`*` wildcard
//!   rule's job, and two spellings of match-everything at one level would be
//!   exactly the ambiguity the overlap rule exists to kill.
//!
//! # Why an automaton
//!
//! Two patterns at one directory level may not both cover any name — the table
//! refuses that at build time, so resolution never adjudicates between them.
//! Deciding it needs the **intersection** of two glob languages, and the
//! obvious shortcut (comparing literal runs) is simply wrong: `ab*` and `*ba`
//! share no run order yet both cover `aba`. [`Pattern::overlaps`] therefore runs
//! a **product construction** over the two patterns' automata — reachability of
//! an accepting pair — with the leading-dot rule encoded *inside* the automata,
//! because a checker that ignores it wrongly refuses `*x` beside `.x*`.
//!
//! Cost, stated honestly: the product is quadratic in the two match lengths and
//! runs over the patterns at one directory level, per mutation and once per
//! load. That is operator-bounded work, and the design records it as such.

use std::fmt;

use super::name::Name;

/// The one metacharacter: any run of bytes, empty included.
const STAR: u8 = b'*';

/// The byte the leading-dot rule is about.
const DOT: u8 = b'.';

/// The glob a pattern rule matches child names with.
///
/// Stored as the operator wrote it — the source form is what the state file
/// keeps, what the control plane echoes and what an error message must name —
/// and matched over its bytes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pattern(String);

impl Pattern {
    /// Validates a match.
    ///
    /// # Errors
    ///
    /// Returns [`PatternError`] for an empty match, a match of only `*`s, and a
    /// match carrying a `/` or a NUL — neither can occur in a host directory
    /// entry, so a match containing one could never cover any name.
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

    /// The match as the operator wrote it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this match covers a child name.
    ///
    /// Byte-wise, with the empty-run and leading-dot rules exactly as the
    /// design pins them.
    #[must_use]
    pub fn covers(&self, name: &Name) -> bool {
        covers_bytes(self.0.as_bytes(), name.as_bytes())
    }

    /// Whether some name is covered by both matches.
    ///
    /// This is the refusal the table's at-most-one-pattern-per-name invariant
    /// rests on. It is decided by reachability over the **product** of the two
    /// automata: a pair of positions is reachable when some common byte string
    /// drives both patterns there, and the two languages intersect exactly when
    /// an accepting pair is reachable. The leading-dot rule rides inside the
    /// step function, so `*x` and `.x*` come out disjoint — as they are.
    ///
    /// The empty string is deliberately not a witness: a host name is never
    /// empty, so acceptance is only ever tested on a pair some byte led to.
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
        // The first byte is the one the leading-dot rule governs, so it is
        // stepped apart from every byte after it.
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

/// Whether a glob's bytes cover a name's bytes.
///
/// **This function is the engine**, and it is deliberately a free function over
/// two byte slices, not a method: the xattr rule surface
/// ([`super::xattr`]) has its own *parser* — a catch-all `*` is legal there and
/// `/` is an ordinary byte — but it matches with this very automaton, so the two
/// languages can never drift into two implementations of one `*`.
///
/// The leading-dot rule rides inside [`step`] and is therefore part of the
/// engine. It is unobservable on attribute names, which the kernel requires to
/// carry a namespace prefix and which can therefore never begin with a `.`.
pub(super) fn covers_bytes(pattern: &[u8], name: &[u8]) -> bool {
    // The automaton's state is the set of pattern positions the input read so
    // far can have reached; `reached[k]` is "position k is live".
    let mut reached = vec![false; pattern.len() + 1];
    for position in closure(pattern, 0) {
        reached[position] = true;
    }
    for (index, byte) in name.iter().enumerate() {
        let start = index == 0;
        let mut next = vec![false; pattern.len() + 1];
        for (position, live) in reached.iter().enumerate() {
            if !live {
                continue;
            }
            let Some(target) = step(pattern, position, *byte, start) else {
                continue;
            };
            for reachable in closure(pattern, target) {
                next[reachable] = true;
            }
        }
        reached = next;
    }
    reached[pattern.len()]
}

/// The positions reachable from `position` without consuming anything: itself,
/// plus everything past a run of `*`s (a `*` may match the empty run).
fn closure(pattern: &[u8], position: usize) -> std::ops::RangeInclusive<usize> {
    let mut end = position;
    while end < pattern.len() && pattern[end] == STAR {
        end += 1;
    }
    position..=end
}

/// Whether the pattern is satisfied at `position`: everything left is `*`.
fn accepts(pattern: &[u8], position: usize) -> bool {
    *closure(pattern, position).end() == pattern.len()
}

/// Where consuming `byte` at `position` leads, or `None` if it cannot.
///
/// `start` marks the first byte of the name, which is where the leading-dot
/// rule applies: only a match whose *own first byte* is a literal `.` may
/// consume a leading `.`, so neither a `*` nor a literal `.` reached by
/// skipping one qualifies.
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

/// Every pair of positions the two automata reach from `(at_left, at_right)`
/// without consuming anything.
fn product(
    left: &[u8],
    right: &[u8],
    at_left: usize,
    at_right: usize,
) -> impl Iterator<Item = (usize, usize)> {
    closure(left, at_left).flat_map(move |a| closure(right, at_right).map(move |b| (a, b)))
}

/// Every pair reachable from `pair` by one byte both patterns accept.
///
/// The byte itself is mostly not materialized: what a transition needs is that
/// *some* byte drives both sides, and each case below names the bytes that do.
/// Where one side is a `*` and the other a literal, the literal fixes the byte;
/// where both are `*`, every byte the dot rule allows leads to the same pair,
/// and there is always at least one such byte.
fn successors(
    left: &[u8],
    right: &[u8],
    pair: (usize, usize),
    start: bool,
) -> impl Iterator<Item = (usize, usize)> {
    let mut reached = Vec::new();
    for (a, b) in product(left, right, pair.0, pair.1) {
        if a == left.len() || b == right.len() {
            // One side is finished and can consume nothing more.
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

/// Why a string is not a valid match.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PatternError {
    /// The match was empty.
    #[error("a match must not be empty")]
    Empty,
    /// The match was nothing but `*`s.
    #[error(
        "a match of only `*` covers every name, which is the `*` rule's job; \
         write a `*` rule on the directory instead"
    )]
    MatchesEverything,
    /// The match contained a `/`.
    #[error("a match covers one child name, so it must not contain a `/` separator")]
    Separator,
    /// The match contained a NUL byte.
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
    fn matching_is_byte_wise_and_the_star_takes_any_run() {
        assert!(covers("project-*", "project-alpha"));
        assert!(covers("project-*", "project-"), "including the empty run");
        assert!(!covers("project-*", "project"));
        assert!(!covers("project-*", "aproject-x"));
        assert!(covers("*-src", "anything-src"));
        assert!(covers("a*b*c", "abc"));
        assert!(covers("a*b*c", "axxbyyc"));
        assert!(!covers("a*b*c", "acb"));
        // Every other byte is literal: no character classes, no escapes.
        assert!(covers("a?c", "a?c"));
        assert!(!covers("a?c", "abc"));
        assert!(covers("[x]", "[x]"));
    }

    #[test]
    fn names_are_bytes_and_never_forced_through_utf8() {
        let raw = Name::new(vec![0xff, 0xfe, b'-', b's', b'r', b'c']).expect("valid name");
        assert!(pattern("*-src").covers(&raw));
        assert!(!pattern("*-doc").covers(&raw));
        // A multibyte match is matched by its bytes, like everything else.
        let unicode = Name::new("café-1").expect("valid name");
        assert!(pattern("café-*").covers(&unicode));
    }

    #[test]
    fn a_leading_star_never_covers_a_dotfile() {
        assert!(!covers("*-a", ".b-a"), "the shell's own rule");
        assert!(!covers("*x", ".x"));
        assert!(!covers("*git", ".git"));
        // A match that begins with a literal `.` does cover dotfiles.
        assert!(covers(".x*", ".xyz"));
        assert!(covers(".x*", ".x"));
        assert!(covers(".*", ".git"));
        assert!(!covers(".*", "git"));
        // A `.` reached by skipping a leading `*` is not "the first byte".
        assert!(!covers("*.x", ".x"));
        assert!(covers("*.x", "a.x"));
        // The rule is about the *leading* dot only.
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

    /// The witness pairs the design pins, each one a case a naive literal-run
    /// comparison gets wrong.
    #[test]
    fn overlap_is_decided_by_the_product_construction() {
        let overlapping = [
            // The pinned counterexample: no shared run order, witness `aba`.
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

    /// The witnesses the overlap answer claims exist really are covered by
    /// both — the checker and the matcher agree, which is what makes the
    /// refusal truthful.
    #[test]
    fn the_pinned_witnesses_are_covered_by_both_patterns() {
        assert!(covers("ab*", "aba") && covers("*ba", "aba"));
        assert!(covers("a*b*c", "abdc") && covers("*d*", "abdc"));
        // And the disjoint pairs have no witness among the names that could
        // plausibly be one.
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

    /// A brute-force cross-check: over a small alphabet, the product
    /// construction agrees with enumerating every name up to a length.
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
                    Name::new(raw.clone())
                        .is_ok_and(|name| left.covers(&name) && right.covers(&name))
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
