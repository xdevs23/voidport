//! Properties that only exist across pieces: insertion-order independence over
//! whole tables, alias directories, and the purity of the engine.

use std::collections::BTreeSet;

use super::mode::{EffectiveMode, ShareMode};
use super::name::Name;
use super::permissions::presented_mode;
use super::resolve::DirContext;
use super::table::{RuleSpec, RuleTable, TableError};
use super::test_support::{describe, dir, enumerate, listing, name, path, table};

fn worked_example() -> RuleTable {
    table([
        RuleSpec::new("/path/to/project", ShareMode::Rw).with_target("/path/to/project"),
        RuleSpec::new("/path/to/project/*", ShareMode::Hidden),
        RuleSpec::new("/path/to/project/foo", ShareMode::Rw),
        RuleSpec::new("/path/to/project/bar", ShareMode::Ro),
        RuleSpec::new("/path/to/project/file.txt", ShareMode::Rw),
    ])
}

fn host_listing() -> [Name; 4] {
    [name("foo"), name("bar"), name("secret"), name("file.txt")]
}

#[test]
fn the_worked_example_resolves_as_documented() {
    let table = worked_example();
    let project = dir(&table, "/path/to/project");

    assert_eq!(
        describe(&table.resolve(&project, &name("foo"))),
        "Rw graft=\"/path/to/project\" relative=\"foo\""
    );
    assert_eq!(
        describe(&table.resolve(&project, &name("bar"))),
        "Ro graft=\"/path/to/project\" relative=\"bar\""
    );
    assert_eq!(
        describe(&table.resolve(&project, &name("file.txt"))),
        "Rw graft=\"/path/to/project\" relative=\"file.txt\""
    );
    assert_eq!(
        describe(&table.resolve(&project, &name("secret"))),
        "Nonexistent"
    );
    assert_eq!(
        describe(&table.resolve(&project, &name("anything-else"))),
        "Nonexistent"
    );
}

#[test]
fn the_worked_example_lists_as_documented() {
    let table = worked_example();
    let project = dir(&table, "/path/to/project");
    assert_eq!(
        listing(&enumerate(&table, &project, host_listing())),
        // In the order the host listing came in, which is not name order.
        [
            r#"foo Rw graft="/path/to/project" relative="foo""#.to_owned(),
            r#"bar Ro graft="/path/to/project" relative="bar""#.to_owned(),
            r#"file.txt Rw graft="/path/to/project" relative="file.txt""#.to_owned(),
        ]
    );
}

#[test]
fn the_worked_example_hides_secret_from_every_direction() {
    let table = worked_example();
    assert_eq!(table.walk(&path("/path/to/project/secret")), None);
    assert_eq!(table.walk(&path("/path/to/project/secret/inner")), None);
    // The host-backed enumerator filters it from the supplied listing. Passing
    // no host names exercises the same state-dispatched entry point and still
    // cannot surface the hidden literal.
    let project = dir(&table, "/path/to/project");
    for listed in [
        enumerate(&table, &project, host_listing()),
        enumerate(&table, &project, []),
    ] {
        assert!(listed.iter().all(|entry| entry.name != name("secret")));
    }
}

#[test]
fn the_worked_example_resolves_whole_paths_as_a_lookup_would() {
    let table = worked_example();
    let resolve = |raw: &str| describe(&table.resolve_path(&path(raw)));

    assert_eq!(resolve("/"), "SynthesizedDir");
    assert_eq!(resolve("/path/to"), "SynthesizedDir");
    assert_eq!(
        resolve("/path/to/project"),
        "Rw graft=\"/path/to/project\" relative=\"\""
    );
    assert_eq!(
        resolve("/path/to/project/bar"),
        "Ro graft=\"/path/to/project\" relative=\"bar\""
    );
    assert_eq!(
        resolve("/path/to/project/bar/deeper"),
        "Ro graft=\"/path/to/project\" relative=\"bar/deeper\""
    );
    assert_eq!(resolve("/path/to/project/secret"), "Nonexistent");
    assert_eq!(resolve("/path/to/project/secret/inner"), "Nonexistent");
    assert_eq!(resolve("/elsewhere"), "Nonexistent");
}

#[test]
fn the_worked_example_presents_the_documented_permission_bits() {
    let table = worked_example();
    let project = dir(&table, "/path/to/project");
    let mode_of = |entry: &str| {
        table
            .resolve(&project, &name(entry))
            .mode()
            .expect("the entry is admitted")
    };
    assert_eq!(presented_mode(0o040_700, mode_of("foo")), 0o040_700);
    assert_eq!(presented_mode(0o040_700, mode_of("bar")), 0o040_500);
    assert_eq!(presented_mode(0o100_600, mode_of("file.txt")), 0o100_600);
}

#[test]
fn mounting_the_example_subpath_walks_synthesized_directories() {
    let table = worked_example();
    assert!(!dir(&table, "/path").backing().is_some());
    assert!(!dir(&table, "/path/to").backing().is_some());
    assert_eq!(
        dir(&table, "/path/to/project").mode(),
        Some(EffectiveMode::Rw)
    );

    assert_eq!(
        listing(&enumerate(&table, &DirContext::root(), [])),
        ["path SynthesizedDir".to_owned()]
    );
    assert_eq!(
        listing(&enumerate(&table, &dir(&table, "/path"), [])),
        ["to SynthesizedDir".to_owned()]
    );
    assert_eq!(
        listing(&enumerate(&table, &dir(&table, "/path/to"), [])),
        [r#"project Rw graft="/path/to/project" relative="""#.to_owned()]
    );
}

#[test]
fn aliased_grafts_resolve_independently_per_namespace_path() {
    let table = table([
        RuleSpec::new("/rw-view", ShareMode::Rw).with_target("/srv/shared"),
        RuleSpec::new("/ro-view", ShareMode::Ro).with_target("/srv/shared"),
        RuleSpec::new("/ro-view/secret", ShareMode::Hidden),
        RuleSpec::new("/rw-view/notes", ShareMode::Ro),
    ]);
    let (writable, readable) = (dir(&table, "/rw-view"), dir(&table, "/ro-view"));

    assert_eq!(
        describe(&table.resolve(&writable, &name("data"))),
        "Rw graft=\"/srv/shared\" relative=\"data\""
    );
    assert_eq!(
        describe(&table.resolve(&readable, &name("data"))),
        "Ro graft=\"/srv/shared\" relative=\"data\""
    );

    assert_eq!(
        describe(&table.resolve(&writable, &name("secret"))),
        "Rw graft=\"/srv/shared\" relative=\"secret\""
    );
    assert_eq!(
        describe(&table.resolve(&readable, &name("secret"))),
        "Nonexistent"
    );
    assert_eq!(
        describe(&table.resolve(&writable, &name("notes"))),
        "Ro graft=\"/srv/shared\" relative=\"notes\""
    );
    assert_eq!(
        describe(&table.resolve(&readable, &name("notes"))),
        "Ro graft=\"/srv/shared\" relative=\"notes\""
    );

    let names = [name("data"), name("secret"), name("notes")];
    assert_eq!(
        listing(&enumerate(&table, &writable, names.clone())),
        [
            r#"data Rw graft="/srv/shared" relative="data""#.to_owned(),
            r#"secret Rw graft="/srv/shared" relative="secret""#.to_owned(),
            r#"notes Ro graft="/srv/shared" relative="notes""#.to_owned(),
        ]
    );
    assert_eq!(
        listing(&enumerate(&table, &readable, names)),
        [
            r#"data Ro graft="/srv/shared" relative="data""#.to_owned(),
            r#"notes Ro graft="/srv/shared" relative="notes""#.to_owned(),
        ]
    );
}

fn permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
    if items.is_empty() {
        return vec![Vec::new()];
    }
    let mut permuted = Vec::new();
    for (index, item) in items.iter().enumerate() {
        let mut rest = items.to_vec();
        rest.remove(index);
        for mut tail in permutations(&rest) {
            tail.insert(0, item.clone());
            permuted.push(tail);
        }
    }
    permuted
}

fn probe_rules() -> Vec<RuleSpec> {
    vec![
        RuleSpec::new("/project", ShareMode::Rw).with_target("/srv/project"),
        RuleSpec::new("/project/*", ShareMode::Hidden),
        RuleSpec::new("/project", ShareMode::Ro).with_match("keep-*"),
        RuleSpec::new("/project/notes.txt", ShareMode::Ro),
        RuleSpec::new("/project/src", ShareMode::Rw),
        RuleSpec::new("/other/deep", ShareMode::Ro).with_target("/srv/other"),
        RuleSpec::new("/nope", ShareMode::Hidden),
    ]
}

fn decisions(table: &RuleTable) -> Vec<String> {
    let directories = ["/", "/project", "/project/src", "/other", "/other/deep"];
    let names = [
        "project",
        "notes.txt",
        "src",
        "other",
        "deep",
        "nope",
        "stranger",
        "keep-one",
        ".keep-one",
    ];
    let mut rendered = Vec::new();
    for raw in directories {
        let namespace_path = path(raw);
        let Some(directory) = table.walk(&namespace_path) else {
            rendered.push(format!("{raw} unreachable"));
            continue;
        };
        rendered.push(format!(
            "{raw} host_backed={}",
            directory.backing().is_some()
        ));
        for entry in names {
            let resolution = table.resolve(&directory, &name(entry));
            rendered.push(format!("{raw} {entry} -> {}", describe(&resolution)));
        }
        rendered.push(format!(
            "{raw} synthesized {:?}",
            listing(&enumerate(table, &directory, []))
        ));
        let host_names: Vec<Name> = names.iter().copied().map(name).collect();
        rendered.push(format!(
            "{raw} host {:?}",
            listing(&enumerate(table, &directory, host_names))
        ));
    }
    rendered
}

#[test]
fn insertion_order_never_changes_a_decision() {
    let reference = table(probe_rules());
    let expected = decisions(&reference);
    let orderings = permutations(&probe_rules());
    assert_eq!(
        orderings.len(),
        5040,
        "every ordering of the seven rules is exercised"
    );
    for ordering in orderings {
        let permuted = table(ordering.clone());
        // The built table itself is order-independent, so every decision that
        // reads it is too. This asserts it directly as well.
        assert_eq!(
            permuted, reference,
            "table differs for ordering {ordering:?}"
        );
        assert_eq!(
            decisions(&permuted),
            expected,
            "decisions differ for ordering {ordering:?}"
        );
    }
}

#[test]
fn insertion_order_never_changes_which_defect_is_reported() {
    let rules = vec![
        RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a"),
        RuleSpec::new("/a/secret", ShareMode::Hidden),
        // Unreachable: it sits under a hidden rule.
        RuleSpec::new("/a/secret/key", ShareMode::Ro),
        // Targetless: no enclosing graft supplies a backing.
        RuleSpec::new("/b/c", ShareMode::Ro),
    ];
    let expected = RuleTable::build(rules.clone()).expect_err("two defects");
    assert!(matches!(expected, TableError::Unreachable { .. }));
    for ordering in permutations(&rules) {
        let error = RuleTable::build(ordering.clone()).expect_err("two defects");
        assert_eq!(error, expected, "error differs for ordering {ordering:?}");
    }
}

/// `include_str!` reads at compile time, so the check below does no I/O. This
/// module is absent from the list because it names the forbidden paths in order
/// to reject them.
const MODULE_SOURCES: [(&str, &str); 10] = [
    ("mod.rs", include_str!("mod.rs")),
    ("mode.rs", include_str!("mode.rs")),
    ("name.rs", include_str!("name.rs")),
    ("ownership.rs", include_str!("ownership.rs")),
    ("path.rs", include_str!("path.rs")),
    ("pattern.rs", include_str!("pattern.rs")),
    ("permissions.rs", include_str!("permissions.rs")),
    ("resolve.rs", include_str!("resolve.rs")),
    ("table.rs", include_str!("table.rs")),
    ("xattr.rs", include_str!("xattr.rs")),
];

const ALLOWED_STD_IMPORTS: [&str; 3] = ["std::collections", "std::fmt", "std::sync"];

const FORBIDDEN_IMPORTS: [&str; 9] = [
    "rustix",
    "tokio",
    "std::env",
    "std::fs",
    "std::io",
    "std::net",
    "std::process",
    "std::thread",
    "std::time",
];

#[test]
fn the_engine_imports_nothing_that_can_touch_the_world() {
    for (module, source) in MODULE_SOURCES {
        for line in source.lines().map(str::trim) {
            let Some(item) = line.strip_prefix("use ") else {
                continue;
            };
            let allowed = item.starts_with("super::")
                || item.starts_with("crate::")
                || ALLOWED_STD_IMPORTS
                    .iter()
                    .any(|prefix| item.starts_with(prefix));
            assert!(
                allowed,
                "{module} imports `{item}`, which the engine may not depend on"
            );
            for forbidden in FORBIDDEN_IMPORTS {
                assert!(
                    !item.starts_with(forbidden),
                    "{module} imports `{item}`, which the engine may not depend on"
                );
            }
        }
    }
}

#[test]
fn every_engine_module_is_covered_by_the_purity_check() {
    let covered: BTreeSet<String> = MODULE_SOURCES
        .iter()
        .map(|(module, _)| (*module).to_owned())
        .collect();
    let declared: BTreeSet<String> = include_str!("mod.rs")
        .lines()
        .filter_map(|line| line.trim().strip_prefix("pub mod "))
        .filter_map(|line| line.strip_suffix(';'))
        .map(|module| format!("{module}.rs"))
        .collect();
    assert!(
        !declared.is_empty(),
        "the module list was parsed from `mod.rs`"
    );
    assert!(
        declared.is_subset(&covered),
        "unchecked engine modules: {:?}",
        declared.difference(&covered).collect::<Vec<_>>()
    );
    assert!(covered.contains("mod.rs"), "`mod.rs` itself is checked too");
}
