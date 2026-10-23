#![forbid(unsafe_code)]
use clap::Parser;
use std::{error::Error, fmt, path::Path, process::ExitCode};
use voidport_lkml::{
    acquire::{self, CollectError},
    cli::{Cli, Command},
    model,
    storage::{Corpus, StorageError},
};

#[derive(Debug, thiserror::Error)]
enum CommandError {
    #[error(transparent)]
    Collect(#[from] CollectError),
    #[error("run collect to convert the corpus to the current format")]
    NeedsCarryOver(#[source] StorageError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

fn open(output: &Path) -> Result<Corpus, CommandError> {
    Corpus::open(output).map_err(|error| match error {
        StorageError::NeedsCarryOver { .. } => CommandError::NeedsCarryOver(error),
        error => error.into(),
    })
}

struct Report<'a>(&'a dyn Error);
impl fmt::Display for Report<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)?;
        let Some(cause) = self.0.source() else {
            return Ok(());
        };
        formatter.write_str("\n\nCaused by:")?;
        let numbered = cause.source().is_some();
        for (number, error) in
            std::iter::successors(Some(cause), |error| (*error).source()).enumerate()
        {
            let (first, continued) = if numbered {
                (format!("{number:>5}: "), "       ")
            } else {
                ("    ".into(), "    ")
            };
            for (index, line) in error.to_string().split('\n').enumerate() {
                let indent = if index == 0 {
                    first.as_str()
                } else {
                    continued
                };
                write!(formatter, "\n{indent}{line}")?;
            }
        }
        Ok(())
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run(Cli::parse().command).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {}", Report(&error));
            ExitCode::FAILURE
        }
    }
}

async fn run(command: Command) -> Result<(), CommandError> {
    match command {
        Command::Collect(options) => Ok(acquire::collect(options).await?),
        Command::Status { output, json } => {
            let corpus = open(&output)?;
            let (partial, attempts) = corpus.inventory()?;
            let status = model::status(corpus.state(), partial, attempts);
            if json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                println!("corpus generation {}", status.generation);
                for source in status.sources {
                    println!("source: {}", source.as_str());
                }
                for unit in &status.units {
                    let completion = if unit.complete {
                        "complete"
                    } else {
                        "unfinished"
                    };
                    println!(
                        "unit: {} {}: {completion}",
                        unit.source.as_str(),
                        unit.query
                    );
                }
                for (name, count) in &status.counts {
                    println!("{name}: {count}");
                }
                for missing in &status.missing_context {
                    println!(
                        "missing context: {} -> {}",
                        missing.source_digest, missing.target_message_id
                    );
                }
                for attempt in status.attempts {
                    println!(
                        "attempt {}: {}; {}; {}",
                        attempt.id, attempt.state, attempt.directory, attempt.cleanup
                    );
                }
                for limitation in status.limitations {
                    println!("{limitation}");
                }
            }
            Ok(())
        }
        Command::Export { output } => {
            let corpus = open(&output)?;
            println!("{}", serde_json::to_string_pretty(&corpus.state().records)?);
            Ok(())
        }
        Command::Verify { output } => {
            let corpus = open(&output)?;
            corpus.verify()?;
            let (partial, attempts) = corpus.inventory()?;
            println!(
                "Verified generation {}: {} committed artifacts; {} partial files; {} retained attempt directories",
                corpus.state().generation,
                corpus.state().records.artifacts.len(),
                partial.len(),
                attempts.len()
            );
            for path in partial {
                println!("partial: {path}");
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Report;

    #[derive(Debug, thiserror::Error)]
    #[error("outer")]
    struct Outer(#[source] Middle);
    #[derive(Debug, thiserror::Error)]
    #[error("middle\nsecond line")]
    struct Middle(#[source] Inner);
    #[derive(Debug, thiserror::Error)]
    #[error("inner")]
    struct Inner;

    #[test]
    fn report_lists_the_sources_and_numbers_several() {
        assert_eq!(Report(&Inner).to_string(), "inner");
        assert_eq!(
            Report(&Middle(Inner)).to_string(),
            "middle\nsecond line\n\nCaused by:\n    inner"
        );
        assert_eq!(
            Report(&Outer(Middle(Inner))).to_string(),
            "outer\n\nCaused by:\n    0: middle\n       second line\n    1: inner"
        );
    }
}
