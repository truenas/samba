// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: GPL-3.0-or-later

//! The header in git is the output of cbindgen for `src/ffi.rs`. The test
//! needs cbindgen on PATH. Without it, the test passes and logs that it
//! did not check the header.

use std::process::Command;

#[test]
fn header_is_current() {
    let dir = env!("CARGO_MANIFEST_DIR");
    let Ok(out) = Command::new("cbindgen")
        .args(["--quiet", "--config", "cbindgen.toml"])
        .current_dir(dir)
        .output()
    else {
        eprintln!("no cbindgen on PATH: the header is not checked");
        return;
    };
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let have = std::fs::read_to_string(format!(
        "{dir}/include/truenas_smbhad_client.h"
    ))
    .unwrap();
    assert!(
        String::from_utf8_lossy(&out.stdout) == have,
        "include/truenas_smbhad_client.h is old, see cbindgen.toml"
    );
}
