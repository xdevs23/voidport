//! Diagnostics go to stderr because `voidport subscribe` writes one JSON object
//! per line on stdout.

use tracing_subscriber::EnvFilter;

pub fn install() {
    tracing_subscriber::fmt()
        .with_env_filter(filter())
        .with_writer(std::io::stderr)
        .init();
}

/// An empty `RUST_LOG` counts as unset, because `EnvFilter::try_from_default_env`
/// parses it into a filter that enables nothing. A value that does not parse
/// falls back the same way.
fn filter() -> EnvFilter {
    let default = || EnvFilter::new("info");
    match std::env::var(EnvFilter::DEFAULT_ENV) {
        Ok(directives) if !directives.trim().is_empty() => {
            EnvFilter::try_new(directives).unwrap_or_else(|_| default())
        }
        _ => default(),
    }
}
