use super::error::{IngestAborted, IngestFailure, MaildirFailure};
use crate::{
    mail,
    model::MaildirFolder,
    staging::AttemptHandle,
    storage::{Directory, Writer},
};
use std::{fmt, io::Read};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScannedFolder {
    Delivered(MaildirFolder),
    /// The folder of mail that is still being delivered. Its files are
    /// checked like the delivered ones and never stored.
    Tmp,
}
impl ScannedFolder {
    const ALL: [Self; 3] = [
        Self::Delivered(MaildirFolder::New),
        Self::Delivered(MaildirFolder::Cur),
        Self::Tmp,
    ];
    fn name(self) -> &'static str {
        match self {
            Self::Delivered(folder) => folder.name(),
            Self::Tmp => "tmp",
        }
    }
}
impl fmt::Display for ScannedFolder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

pub(super) fn ingest(
    corpus: &mut Writer,
    attempt: AttemptHandle,
    directory: &Directory,
) -> Result<(), Box<IngestFailure>> {
    let mut failures = Vec::new();
    match store(corpus, attempt, directory, &mut failures) {
        Ok(()) if failures.is_empty() => Ok(()),
        result => Err(Box::new(IngestFailure {
            failures,
            aborted: result.err(),
        })),
    }
}

fn store(
    corpus: &mut Writer,
    attempt: AttemptHandle,
    directory: &Directory,
    failures: &mut Vec<MaildirFailure>,
) -> Result<(), IngestAborted> {
    let maildir = directory
        .child("maildir")
        .map_err(IngestAborted::OpenMaildir)?;
    for name in maildir.entries().map_err(IngestAborted::ListMaildir)? {
        if !ScannedFolder::ALL
            .iter()
            .any(|folder| name == folder.name())
        {
            return Err(IngestAborted::UnexpectedEntry { name });
        }
    }
    for folder in ScannedFolder::ALL {
        let directory = match maildir.child(folder.name()) {
            Ok(directory) => directory,
            Err(source) => {
                failures.push(MaildirFailure::Folder { folder, source });
                continue;
            }
        };
        let entries = match directory.entries() {
            Ok(entries) => entries,
            Err(source) => {
                failures.push(MaildirFailure::List { folder, source });
                continue;
            }
        };
        for filename in entries {
            let mut input = match directory.maildir_input(&filename) {
                Ok(input) => input,
                Err(source) => {
                    failures.push(MaildirFailure::Open {
                        name: filename,
                        source,
                    });
                    continue;
                }
            };
            let ScannedFolder::Delivered(delivered) = folder else {
                continue;
            };
            let mut bytes = Vec::new();
            if let Err(source) = input.read_to_end(&mut bytes) {
                failures.push(MaildirFailure::Read {
                    name: filename,
                    source,
                });
                continue;
            }
            let artifact = match corpus.store(&bytes) {
                Ok(artifact) => artifact,
                Err(source) => {
                    return Err(IngestAborted::Store {
                        folder: delivered,
                        name: filename,
                        source,
                    });
                }
            };
            if artifact.metadata.class == mail::Class::Invalid {
                failures.push(MaildirFailure::InvalidMail {
                    digest: artifact.digest.clone(),
                });
            }
            corpus
                .deliver(attempt, delivered, &filename, artifact)
                .map_err(IngestAborted::Deliver)?;
        }
    }
    Ok(())
}
