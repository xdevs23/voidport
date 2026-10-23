use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use voidport_control::NamespaceName;

use super::Environment;
use super::build::{NamespaceError, build_namespace};
use super::document::{ServerSettingsError, StateDocument};
use crate::records::{RecordError, RecordHome};
use crate::registry::Registry;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedState {
    pub document: StateDocument,
    pub registry: Registry,
}

/// # Errors
///
/// Returns a [`LoadError`] naming the file and, where it applies, the
/// namespace and rule at fault.
pub fn load(path: &Path, environment: &Environment) -> Result<LoadedState, LoadError> {
    let document = load_document(path)?;
    let registry = validate(&document, environment, &RecordHome::for_state_file(path))?;
    Ok(LoadedState { document, registry })
}

/// # Errors
///
/// Returns [`LoadError::Io`] if the file cannot be read and
/// [`LoadError::Parse`] if it is not a valid state document. A missing file is
/// an error here: loading never invents a document.
pub fn load_document(path: &Path) -> Result<StateDocument, LoadError> {
    let text = fs::read_to_string(path).map_err(|source| LoadError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    StateDocument::from_toml(&text).map_err(|source| LoadError::Parse {
        path: path.to_path_buf(),
        source: Box::new(source),
    })
}

/// # Errors
///
/// Returns [`LoadError::ServerSettings`] for a server setting that is not usable,
/// [`LoadError::DuplicateNamespace`] if a name repeats,
/// [`LoadError::Namespace`] for the first namespace the engine rejects, and
/// [`LoadError::Records`] for a record sidecar that cannot be read.
///
/// `home` is where the record sidecar of each namespace lives. A store is opened
/// once per name here, and the mutation path reuses the stores it already has.
pub fn validate(
    document: &StateDocument,
    environment: &Environment,
    home: &RecordHome,
) -> Result<Registry, LoadError> {
    document
        .server
        .validate()
        .map_err(|source| LoadError::ServerSettings { source })?;
    if let Some(name) = document.duplicate_namespace() {
        return Err(LoadError::DuplicateNamespace { name: name.clone() });
    }
    let mut registry = Registry::new();
    for spec in &document.namespaces {
        let namespace =
            build_namespace(spec, environment).map_err(|source| LoadError::Namespace {
                namespace: spec.name.clone(),
                source,
            })?;
        registry
            .insert(namespace, home)
            .map_err(|source| LoadError::Records {
                namespace: spec.name.clone(),
                source,
            })?;
    }
    Ok(registry)
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LoadError {
    #[error("cannot read state file {path}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid state file {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: Box<toml::de::Error>,
    },
    #[error("{source}")]
    ServerSettings {
        #[source]
        source: ServerSettingsError,
    },
    #[error("namespace \"{name}\" is declared twice")]
    DuplicateNamespace { name: NamespaceName },
    #[error("namespace \"{namespace}\": {source}")]
    Namespace {
        namespace: NamespaceName,
        #[source]
        source: NamespaceError,
    },
    #[error("namespace \"{namespace}\": {source}")]
    Records {
        namespace: NamespaceName,
        #[source]
        source: RecordError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::render;
    use voidport_test_host::Scratch;

    fn environment() -> Environment {
        Environment::new(1000, 100, "/srv/state")
    }

    fn home() -> RecordHome {
        RecordHome::for_state_file(
            &std::env::temp_dir().join(format!("voidport-load-{}.toml", std::process::id())),
        )
    }

    fn document(text: &str) -> StateDocument {
        StateDocument::from_toml(text).expect("parses")
    }

    #[test]
    fn a_valid_document_builds_every_namespace() {
        let scratch = Scratch::new("load");
        scratch.directory("project");
        let document = document(
            r#"
            [[namespaces]]
            name = "project"
            [[namespaces.rules]]
            path = "/project"
            mode = "rw"
            target = "project"

            [[namespaces]]
            name = "scratch"
            "#,
        );
        let registry = validate(
            &document,
            &Environment::new(1000, 100, scratch.path()),
            &RecordHome::for_state_file(&scratch.join("state.toml")),
        )
        .expect("valid");
        assert_eq!(registry.len(), 2);
        let names: Vec<&str> = registry
            .iter()
            .map(|namespace| namespace.name().as_str())
            .collect();
        assert_eq!(names, ["project", "scratch"]);
    }

    #[test]
    fn a_dead_configuration_names_its_namespace_and_rule() {
        let document = document(
            r#"
            [[namespaces]]
            name = "project"
            [[namespaces.rules]]
            path = "/a"
            mode = "rw"
            target = "/srv/a"
            [[namespaces.rules]]
            path = "/a/secret"
            mode = "hidden"
            [[namespaces.rules]]
            path = "/a/secret/key"
            mode = "ro"
            "#,
        );
        let error = validate(&document, &environment(), &home()).expect_err("dead configuration");
        let rendered = render(&error);
        assert!(rendered.contains("\"project\""), "{rendered}");
        assert!(rendered.contains("/a/secret/key"), "{rendered}");
        assert!(matches!(error, LoadError::Namespace { .. }));
    }

    #[test]
    fn duplicate_namespaces_are_rejected() {
        let document = document(
            r#"
            [[namespaces]]
            name = "project"
            [[namespaces]]
            name = "project"
            "#,
        );
        let error = validate(&document, &environment(), &home()).expect_err("duplicate");
        assert!(matches!(error, LoadError::DuplicateNamespace { .. }));
        assert!(error.to_string().contains("\"project\""), "{error}");
    }

    #[test]
    fn loading_a_missing_file_is_an_error_not_an_invented_document() {
        let error =
            load_document(Path::new("/nonexistent/voidport/state.toml")).expect_err("no such file");
        assert!(matches!(error, LoadError::Io { .. }));
        assert!(error.to_string().contains("state.toml"), "{error}");
    }

    #[test]
    fn a_parse_error_names_the_file() {
        let directory = std::env::temp_dir();
        let path = directory.join(format!("voidport-parse-{}.toml", std::process::id()));
        fs::write(&path, "this is not toml").expect("writable temp file");
        let error = load_document(&path).expect_err("not a state document");
        fs::remove_file(&path).expect("cleanup");
        assert!(matches!(error, LoadError::Parse { .. }));
        assert!(error.to_string().contains("voidport-parse"), "{error}");
    }

    #[test]
    fn a_file_with_a_server_limits_table_is_refused_and_the_error_names_it() {
        let directory = std::env::temp_dir();
        for (label, text) in [
            ("empty", "[server.limits]\n"),
            ("set", "[server.limits]\nmax_nodes = 8\n"),
        ] {
            let path = directory.join(format!(
                "voidport-limits-{label}-{}.toml",
                std::process::id()
            ));
            fs::write(&path, text).expect("writable temp file");
            let error = load_document(&path).expect_err("an unknown field");
            fs::remove_file(&path).expect("cleanup");
            assert!(matches!(error, LoadError::Parse { .. }), "{error}");
            assert!(error.to_string().contains("`limits`"), "{label}: {error}");
        }
    }
}
