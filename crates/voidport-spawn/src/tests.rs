use std::fs;
use std::io::{BufRead as _, BufReader, Read as _};
use std::os::fd::AsFd as _;
use std::path::PathBuf;

use rustix::pty::OpenptFlags;

use super::*;

fn target(pid: u32, number: RawFd) -> PathBuf {
    fs::read_link(format!("/proc/{pid}/fd/{number}")).expect("the descriptor is open")
}

#[test]
fn a_child_gets_exactly_the_descriptors_given_at_their_numbers() {
    let (third, _third) = io::pipe().expect("a pipe");
    let (seventh, _seventh) = io::pipe().expect("a pipe");
    let inherited = rustix::io::fcntl_dupfd_cloexec(&third, 10).expect("a copy");
    rustix::io::fcntl_setfd(&inherited, rustix::io::FdFlags::empty())
        .expect("close-on-exec is cleared");

    // The shell reports once it waits for its input, and then opens nothing
    // until that input ends, with which it succeeds.
    let mut child = Program::new("sh")
        .args(["-c", "echo waiting; read -r line || true"])
        .stdin(Stream::Piped)
        .stdout(Stream::Piped)
        .descriptor(3, third.as_fd())
        .descriptor(7, seventh.as_fd())
        .spawn()
        .expect("sh starts");
    let mut waiting = String::new();
    let _read = BufReader::new(child.stdout.take().expect("a piped stdout"))
        .read_line(&mut waiting)
        .expect("the child reports");
    assert_eq!(waiting, "waiting\n");

    let mut numbers = fs::read_dir(format!("/proc/{}/fd", child.id()))
        .expect("the descriptors of the child are listed")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .into_string()
                .expect("a number")
                .parse::<RawFd>()
                .expect("a number")
        })
        .collect::<Vec<_>>();
    numbers.sort_unstable();
    assert_eq!(numbers, [0, 1, 2, 3, 7]);
    let ours = std::process::id();
    assert_eq!(target(child.id(), 3), target(ours, third.as_raw_fd()));
    assert_eq!(target(child.id(), 7), target(ours, seventh.as_raw_fd()));
    assert_eq!(target(child.id(), 2), PathBuf::from("/dev/null"));

    drop(child.stdin.take());
    assert!(child.wait().expect("the child ends").success());
}

#[test]
fn a_descriptor_at_the_number_of_a_standard_stream_is_refused() {
    let (reader, _writer) = io::pipe().expect("a pipe");
    let refused = Program::new("true").descriptor(2, reader.as_fd()).spawn();
    assert!(matches!(refused, Err(SpawnError::StandardStream(2))));
}

#[test]
fn the_output_and_the_status_of_a_child_are_returned() {
    let output = Program::new("sh")
        .args(["-c", "echo out; echo err >&2; exit 3"])
        .output()
        .expect("sh starts");
    assert_eq!(output.stdout, b"out\n");
    assert_eq!(output.stderr, b"err\n");
    assert_eq!(output.status.code(), Some(3));

    let status = Program::new("sh")
        .args(["-c", "exit 4"])
        .status()
        .expect("sh starts");
    assert_eq!(status.code(), Some(4));
}

#[test]
fn a_program_run_through_a_wrapper_follows_the_arguments_of_the_wrapper() {
    let output = Program::new("echo")
        .arg("program")
        .run_through("echo", ["wrapper"])
        .output()
        .expect("echo starts");
    assert_eq!(output.stdout, b"wrapper echo program\n");
}

fn waiting(program: &mut Program<'_>) -> Child {
    program
        .args(["-c", "read -r line || true"])
        .stdin(Stream::Piped)
        .spawn()
        .expect("sh starts")
}

fn environment_of(child: &Child) -> Vec<String> {
    fs::read(format!("/proc/{}/environ", child.id()))
        .expect("the environment of the child is readable")
        .split(|&byte| byte == 0)
        .filter(|variable| !variable.is_empty())
        .map(|variable| String::from_utf8_lossy(variable).into_owned())
        .collect()
}

fn finish(mut child: Child) {
    drop(child.stdin.take());
    assert!(child.wait().expect("the child ends").success());
}

#[test]
fn the_environment_of_a_child_follows_the_calls() {
    let child = waiting(
        Program::new("sh")
            .env("VOIDPORT_SPAWN_KEPT", "1")
            .env("VOIDPORT_SPAWN_REMOVED", "2")
            .env_remove("VOIDPORT_SPAWN_REMOVED"),
    );
    let inherited = std::env::vars_os().count();
    let environment = environment_of(&child);
    assert_eq!(environment.len(), inherited + 1);
    assert!(environment.contains(&"VOIDPORT_SPAWN_KEPT=1".to_owned()));
    finish(child);

    let child = waiting(
        Program::new("sh")
            .env("VOIDPORT_SPAWN_BEFORE", "1")
            .env_clear()
            .env("VOIDPORT_SPAWN_AFTER", "2"),
    );
    assert_eq!(environment_of(&child), ["VOIDPORT_SPAWN_AFTER=2"]);
    finish(child);
}

#[test]
fn a_child_runs_in_the_working_directory_given() {
    let directory = fs::canonicalize(std::env::temp_dir()).expect("a temporary directory");
    let child = waiting(Program::new("sh").current_dir(&directory));
    let working = fs::read_link(format!("/proc/{}/cwd", child.id())).expect("the directory");
    assert_eq!(working, directory);
    finish(child);
}

#[test]
fn a_child_in_a_new_session_has_its_input_as_the_controlling_terminal() {
    let flags = OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC;
    let terminal = rustix::pty::openpt(flags).expect("a pseudoterminal");
    rustix::pty::unlockpt(&terminal).expect("the pseudoterminal is unlocked");
    let input = rustix::pty::ioctl_tiocgptpeer(&terminal, flags).expect("its other end");

    // `/dev/tty` opens only the terminal that controls the calling process.
    let mut child = Program::new("sh")
        .args(["-c", "echo controlled > /dev/tty"])
        .stdin(Stream::Descriptor(input.as_fd()))
        .in_new_session_on_terminal()
        .spawn()
        .expect("sh starts");
    drop(input);
    assert!(child.wait().expect("the child ends").success());

    // Once no process has the other end open, a read fails instead of
    // returning an end of file.
    let mut shown = Vec::new();
    let _error = fs::File::from(terminal).read_to_end(&mut shown);
    assert!(
        String::from_utf8_lossy(&shown).contains("controlled"),
        "{shown:?}"
    );
}

#[test]
fn a_child_in_a_new_session_does_not_start_on_an_input_that_is_not_a_terminal() {
    let refused = Program::new("sh")
        .args(["-c", "echo started"])
        .stdin(Stream::Null)
        .in_new_session_on_terminal()
        .output();
    assert!(
        matches!(refused, Err(SpawnError::Program(_))),
        "{refused:?}"
    );
}
