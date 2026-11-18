// Copyright (C) iXsystems, Inc. 2026
// SPDX-License-Identifier: MIT

//! This test checks that `include/truenas_smbros.h` matches the output of
//! cbindgen for `src/`. It needs cbindgen on PATH. Without cbindgen, the
//! test passes and logs that it did not check the header.

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
    let have =
        std::fs::read_to_string(format!("{dir}/include/truenas_smbros.h"))
            .unwrap();
    assert!(
        String::from_utf8_lossy(&out.stdout) == have,
        "include/truenas_smbros.h is old, see cbindgen.toml"
    );
}
