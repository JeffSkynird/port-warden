use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::{fs, process::Command, time::{SystemTime, UNIX_EPOCH}};

#[test]
fn prints_ports_from_env() {
    // Run from a clean temp directory so it won't find .portkill.json upward
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let tmp = std::env::temp_dir().join(format!("pw-test-{}", nanos));
    fs::create_dir_all(&tmp).unwrap();

    let mut cmd = Command::cargo_bin("port-warden").unwrap();
    cmd.current_dir(&tmp)
        .env("PORTKILL_PORTS", "3001,3002")
        .arg("list");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Puertos: [3001, 3002]"));
}
