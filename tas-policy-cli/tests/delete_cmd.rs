// Tests for the `delete` subcommand (CLI integration).

use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;

fn cmd() -> assert_cmd::Command {
    cargo_bin_cmd!("tas-policy")
}

// ─── Argument validation ─────────────────────────────────────────────────────

#[test]
fn delete_requires_policy_key() {
    // `delete` without --policy-key should fail with a usage error
    cmd()
        .arg("delete")
        .assert()
        .failure()
        .stderr(predicate::str::contains("--policy-key"));
}

#[test]
fn delete_help_shows_policy_key_option() {
    cmd()
        .args(["delete", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--policy-key"));
}
