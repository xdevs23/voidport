use super::{DirectoryError, InvalidComponent};
use rustix::fs::{self, Mode, OFlags};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    fs::File,
    io::Read,
    os::{fd::AsRawFd, unix::ffi::OsStrExt},
    path::Path,
};

pub struct Directory(pub File);
impl Directory {
    pub fn open(path: &Path) -> Result<Self, DirectoryError> {
        let directory = fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(DirectoryError::Open)?;
        Ok(Self(File::from(directory)))
    }
    pub fn child(&self, name: impl AsRef<OsStr>) -> Result<Self, DirectoryError> {
        component(name.as_ref())?;
        let directory = fs::openat(
            &self.0,
            name.as_ref(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(DirectoryError::Open)?;
        Ok(Self(File::from(directory)))
    }
    pub fn create(&self, name: &str) -> Result<(), DirectoryError> {
        component(OsStr::new(name))?;
        fs::mkdirat(&self.0, name, Mode::RUSR | Mode::WUSR | Mode::XUSR)
            .map_err(DirectoryError::Create)?;
        self.sync()
    }
    pub fn mkdir(&self, name: &str) -> Result<Self, DirectoryError> {
        self.create(name)?;
        self.child(name)
    }
    pub fn file(&self, name: impl AsRef<OsStr>, flags: OFlags) -> Result<File, DirectoryError> {
        component(name.as_ref())?;
        let file = File::from(
            fs::openat(
                &self.0,
                name.as_ref(),
                flags | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(DirectoryError::Open)?,
        );
        let stat = fs::fstat(&file).map_err(DirectoryError::Stat)?;
        if fs::FileType::from_raw_mode(stat.st_mode) != fs::FileType::RegularFile
            || stat.st_nlink != 1
        {
            return Err(DirectoryError::LinkedOrIrregularFile);
        }
        Ok(file)
    }
    /// Delivered Maildir files may have aliases; they are copied, never adopted.
    pub fn maildir_input(&self, name: impl AsRef<OsStr>) -> Result<File, DirectoryError> {
        component(name.as_ref())?;
        let file = File::from(
            fs::openat(
                &self.0,
                name.as_ref(),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(DirectoryError::Open)?,
        );
        let mode = fs::fstat(&file).map_err(DirectoryError::Stat)?.st_mode;
        if fs::FileType::from_raw_mode(mode) != fs::FileType::RegularFile {
            return Err(DirectoryError::IrregularMaildirInput);
        }
        Ok(file)
    }
    pub fn check_file(&self, name: impl AsRef<OsStr>) -> Result<(), DirectoryError> {
        let _checked = self.file(name, OFlags::RDONLY)?;
        Ok(())
    }
    pub fn read(&self, name: impl AsRef<OsStr>) -> Result<Vec<u8>, DirectoryError> {
        let mut bytes = Vec::new();
        self.file(name, OFlags::RDONLY)?
            .read_to_end(&mut bytes)
            .map_err(DirectoryError::Read)?;
        Ok(bytes)
    }
    pub fn entries(&self) -> Result<Vec<std::ffi::OsString>, DirectoryError> {
        let mut names = Vec::new();
        for entry in fs::Dir::read_from(&self.0).map_err(DirectoryError::List)? {
            let entry = entry.map_err(DirectoryError::List)?;
            let bytes = entry.file_name().to_bytes();
            if bytes != b"." && bytes != b".." {
                names.push(OsStr::from_bytes(bytes).to_os_string());
            }
        }
        names.sort();
        Ok(names)
    }
    pub fn exists(&self, name: &str) -> Result<bool, DirectoryError> {
        component(OsStr::new(name))?;
        match fs::statat(&self.0, name, fs::AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Ok(true),
            Err(rustix::io::Errno::NOENT) => Ok(false),
            Err(error) => Err(DirectoryError::Stat(error)),
        }
    }
    pub fn sync(&self) -> Result<(), DirectoryError> {
        self.0.sync_all().map_err(DirectoryError::Sync)
    }
    pub fn process_path(&self) -> String {
        format!("/proc/{}/fd/{}", std::process::id(), self.0.as_raw_fd())
    }
}
pub(super) fn component(name: &OsStr) -> Result<(), InvalidComponent> {
    if matches!(
        Path::new(name).components().collect::<Vec<_>>().as_slice(),
        [std::path::Component::Normal(_)]
    ) {
        Ok(())
    } else {
        Err(InvalidComponent)
    }
}
pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub(super) fn valid_digest(value: &str) -> bool {
    hex::decode(value).is_ok_and(|bytes| bytes.len() == 32 && hex::encode(bytes) == value)
}
