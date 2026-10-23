//! Only `*` is a metacharacter.

const STAR: u8 = b'*';
const DOT: u8 = b'.';

/// Only a literal leading dot covers a leading dot, as in the child-pattern
/// automaton used for overlap analysis. Attribute names cannot begin with a dot,
/// so that rule does not apply to xattrs.
///
/// The prefix and suffix are anchored. Between them, each literal run takes
/// its earliest match: a later match cannot leave more room for the next run.
/// `memmem` searches in linear time, and each successful search consumes the
/// bytes it searched. Total work is linear in pattern plus name length, even
/// for arbitrarily long runs of stars.
pub(super) fn covers_bytes(pattern: &[u8], name: &[u8]) -> bool {
    if name.first() == Some(&DOT) && pattern.first() != Some(&DOT) {
        return false;
    }
    let mut runs = pattern.split(|byte| *byte == STAR);
    let prefix = runs.next().expect("split always has a first item");
    let Some(suffix) = runs.next_back() else {
        return name == prefix;
    };
    let Some(mut remaining) = name
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_suffix(suffix))
    else {
        return false;
    };
    for literal in runs.filter(|run| !run.is_empty()) {
        let Some(at) = memchr::memmem::find(remaining, literal) else {
            return false;
        };
        remaining = &remaining[at + literal.len()..];
    }
    true
}

#[cfg(test)]
mod tests {
    use super::covers_bytes;

    fn covers(pattern: &str, name: &str) -> bool {
        covers_bytes(pattern.as_bytes(), name.as_bytes())
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
        assert!(covers("a?c", "a?c"));
        assert!(!covers("a?c", "abc"));
        assert!(covers("[x]", "[x]"));
    }

    #[test]
    fn long_repeated_stars_match_short_and_maximum_length_xattr_names() {
        let stars = "*".repeat(100_000);
        let raw = format!("user.{stars}id{stars}");
        let maximum = format!("user.{}id", "a".repeat(248));
        assert_eq!(maximum.len(), 255);
        for name in [b"user.id".as_slice(), maximum.as_bytes()] {
            assert!(covers_bytes(raw.as_bytes(), name));
            assert!(covers_bytes(stars.as_bytes(), name));
            assert!(!covers_bytes(format!("{raw}missing").as_bytes(), name));
        }
        assert!(!covers_bytes(stars.as_bytes(), b".hidden"));
        assert!(covers_bytes(format!(".{stars}").as_bytes(), b".hidden"));
    }

    #[test]
    fn literal_runs_do_not_overlap_and_the_suffix_stays_anchored() {
        assert!(!covers("ab*bc", "abc"));
        assert!(covers("ab*bc", "abbc"));
        assert!(covers("*ab*ab", "abab"));
        assert!(!covers("*ab*ab", "ab"));
        assert!(covers("*ab*ab", "abxxabab"));
        assert!(!covers("*ab*ab", "ababx"));
        let repeated = format!("*{}b*", "a".repeat(10_000));
        assert!(!covers_bytes(repeated.as_bytes(), &vec![b'a'; 100_000]));
    }
}
