#[test]
fn filesystem_cleanup_attempts_detach_and_reports_every_failure() {
    let output = voidport_spawn::Program::new("python3")
        .args(["-c", include_str!("../filesystem-cleanup-check")])
        .env(
            "LKML_FILESYSTEM_HARNESS",
            include_str!("../filesystem-check"),
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
