//! Loading a state file.
//!
//! Loading is read, parse, then validate **every** namespace through the
//! engine's build boundary — a state file that would produce a namespace the
//! server cannot serve refuses startup instead of starting degraded.
//!
//! Error enrichment is the loader's job. The layers below produce precise but
//! context-free errors: `toml` knows the line and column but not the meaning,
//! the rule engine knows the offending rule path but not the namespace. This
//! module joins them, so an operator reads
//! `state.toml: namespace "project": rule table: rule /a/b is unreachable: …`
//! and knows exactly what to edit.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use voidport_control::NamespaceName;

use super::Environment;
use super::build::{NamespaceError, build_namespace};
use super::document::StateDocument;
use super::limits::LimitsError;
use crate::registry::Registry;

/// A state file, loaded and built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedState {
    /// The source document, exactly as the file holds it.
    pub document: StateDocument,
    /// Its built namespaces.
    pub registry: Registry,
}

/// Reads, parses and builds a state file.
///
/// # Errors
///
/// Returns a [`LoadError`] naming the file and, where it applies, the
/// namespace and rule at fault.
pub fn load(path: &Path, environment: &Environment) -> Result<LoadedState, LoadError> {
    let document = load_document(path)?;
    let registry = validate(&document, environment)?;
    Ok(LoadedState { document, registry })
}

/// Reads and parses a state file without building it.
///
/// # Errors
///
/// Returns [`LoadError::Io`] if the file cannot be read and
/// [`LoadError::Parse`] if it is not a valid state document. A missing file is
/// an error here: loading never invents a document. Creating a *cleanly*
/// missing one is a separate, deliberate step the daemon takes before this one
/// (see [`create_if_missing`](super::create_if_missing)).
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

/// Builds every namespace of a document, rejecting duplicates.
///
/// # Errors
///
/// Returns [`LoadError::ServerSettings`] for a cap the server cannot honour,
/// [`LoadError::DuplicateNamespace`] if a name repeats, and
/// [`LoadError::Namespace`] for the first namespace the engine rejects.
pub fn validate(
    document: &StateDocument,
    environment: &Environment,
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
        registry.insert(namespace);
    }
    Ok(registry)
}

/// Why a state file cannot be loaded.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LoadError {
    /// The file could not be read.
    #[error("cannot read state file {path}")]
    Io {
        /// The state file.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },
    /// The file is not a valid state document. The inner error carries the
    /// offending line and column.
    #[error("invalid state file {path}: {source}")]
    Parse {
        /// The state file.
        path: PathBuf,
        /// Why it was rejected.
        #[source]
        source: Box<toml::de::Error>,
    },
    /// A server setting is not usable as written.
    #[error("{source}")]
    ServerSettings {
        /// Why it was rejected.
        #[source]
        source: LimitsError,
    },
    /// Two namespaces share a name, so the registry keyspace is ambiguous.
    #[error("namespace \"{name}\" is declared twice")]
    DuplicateNamespace {
        /// The repeated name.
        name: NamespaceName,
    },
    /// A namespace does not build.
    #[error("namespace \"{namespace}\": {source}")]
    Namespace {
        /// The namespace at fault.
        namespace: NamespaceName,
        /// Why it does not build.
        #[source]
        source: NamespaceError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::render;
    use crate::testing::Scratch;

    fn environment() -> Environment {
        Environment::new(1000, 100, "/srv/state")
    }

    fn document(text: &str) -> StateDocument {
        StateDocument::from_toml(text).expect("parses")
    }

    #[test]
    fn a_valid_document_builds_every_namespace() {
        // Building pins graft targets, so the relative target below resolves
        // into a directory that exists.
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
        let registry =
            validate(&document, &Environment::new(1000, 100, scratch.path())).expect("valid");
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
        let error = validate(&document, &environment()).expect_err("dead configuration");
        let rendered = render(&error);
        assert!(rendered.contains("\"project\""), "{rendered}");
        assert!(rendered.contains("/a/secret/key"), "{rendered}");
        assert!(matches!(error, LoadError::Namespace { .. }));
    }

    #[test]
    fn a_cap_the_server_cannot_honour_refuses_the_file() {
        let document = document(
            r#"
            [server.limits]
            max_inflight = 0
            "#,
        );
        let error = validate(&document, &environment()).expect_err("zero is not a cap");
        assert!(matches!(error, LoadError::ServerSettings { .. }));
        assert!(error.to_string().contains("max_inflight"), "{error}");
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
        let error = validate(&document, &environment()).expect_err("duplicate");
        assert!(matches!(error, LoadError::DuplicateNamespace { .. }));
        assert!(error.to_string().contains("\"project\""), "{error}");
    }

    #[test]
    fn loading_a_missing_file_is_an_error_rather_than_an_invented_document() {
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
}
