use crate::{collector::*, corpus::*};
use std::{
    ffi::OsStr,
    fs,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, symlink},
    },
};
use voidport_lkml::storage::{DataDirectory, Writer};

#[test]
fn attempt_inventory_reports_only_canonical_directories_without_mutation() {
    for (name, kind, valid) in [
        (b"00000000000000000001".as_slice(), "directory", true),
        (b"18446744073709551615", "directory", true),
        (b"notes", "directory", false),
        (b"1", "directory", false),
        (b"00000000000000000000", "directory", false),
        (b"+0000000000000000001", "directory", false),
        (b"18446744073709551616", "directory", false),
        (b"000000000000000000001", "directory", false),
        (b"0000000000000000000\xff", "directory", false),
        (b"00000000000000000001", "file", false),
        (b"00000000000000000001", "symlink", false),
    ] {
        let fixture = Fixture::new();
        let corpus = Writer::open(&fixture.output, configuration(&["q"])).unwrap();
        let _created = corpus.data_dir(DataDirectory::Attempts).unwrap();
        drop(corpus);
        let path = fixture
            .output
            .join("attempts")
            .join(OsStr::from_bytes(name));
        let outside = fixture.temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("keep"), b"outside bytes").unwrap();
        match kind {
            "directory" => {
                fs::create_dir(&path).unwrap();
                fs::write(path.join("keep"), b"partial work").unwrap();
            }
            "file" => fs::write(&path, b"foreign file").unwrap(),
            "symlink" => symlink(&outside, &path).unwrap(),
            _ => unreachable!(),
        }
        let before = fs::read(fixture.output.join("manifest.json")).unwrap();
        let identity = fs::symlink_metadata(&path).unwrap();
        fs::remove_file(&fixture.client).unwrap();
        for operation in ["status", "verify"] {
            let mut command = fixture.command(operation);
            if operation == "status" {
                command.arg("--json");
            }
            let output = command.output().unwrap();
            assert_eq!(
                output.status.success(),
                valid,
                "{name:?} {kind} {operation}"
            );
            if valid && operation == "status" {
                let status: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(
                    status["retained_attempt_directories"],
                    serde_json::json!([format!("attempts/{}", std::str::from_utf8(name).unwrap())])
                );
                assert_eq!(status["attempts"], serde_json::json!([]));
            }
            assert_eq!(
                fs::read(fixture.output.join("manifest.json")).unwrap(),
                before
            );
            let after = fs::symlink_metadata(&path).unwrap();
            assert_eq!(after.ino(), identity.ino());
            assert_eq!(after.mode(), identity.mode());
            assert_eq!(after.mtime(), identity.mtime());
            assert_eq!(after.mtime_nsec(), identity.mtime_nsec());
            assert_eq!(
                fs::read_dir(fixture.output.join("attempts"))
                    .unwrap()
                    .count(),
                1
            );
            match kind {
                "directory" => assert_eq!(fs::read(path.join("keep")).unwrap(), b"partial work"),
                "file" => assert_eq!(fs::read(&path).unwrap(), b"foreign file"),
                "symlink" => assert_eq!(fs::read_link(&path).unwrap(), outside),
                _ => unreachable!(),
            }
            assert_eq!(fs::read(outside.join("keep")).unwrap(), b"outside bytes");
        }
    }
}
