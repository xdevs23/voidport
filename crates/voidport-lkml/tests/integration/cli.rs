use clap::{CommandFactory, Parser};
use voidport_lkml::cli::{Cli, Command};

#[test]
fn required_paths_and_positive_durations() {
    Cli::command().debug_assert();
    for command in ["collect", "status", "verify"] {
        assert!(Cli::try_parse_from(["voidport-lkml", command]).is_err());
    }
    for flag in ["--timeout-seconds", "--delay-seconds"] {
        assert!(
            Cli::try_parse_from(["voidport-lkml", "collect", "--output", "corpus", flag, "0"])
                .is_err()
        );
    }
    let Cli {
        command: Command::Collect(args),
    } = Cli::try_parse_from(["voidport-lkml", "collect", "--output", "corpus"]).unwrap()
    else {
        panic!()
    };
    assert_eq!(args.timeout_seconds.get(), 1800);
    assert_eq!(args.delay_seconds.get(), 5);
    assert!(args.source.is_empty() && args.query.is_empty() && args.author.is_empty());
}
