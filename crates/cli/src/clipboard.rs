//! The Wayland clipboard, through `wl-copy` and `wl-paste` (wl-clipboard).
//!
//! A copied secret is cleared after a delay by a detached child of this
//! binary (`passforme __clear-clipboard`), which clears it only if the
//! clipboard still holds the same secret, so something the user copied in
//! the meantime is left alone. The child learns which secret by its SHA-256
//! on stdin, never on its command line, where `ps` would show it.
//!
//! The secret goes to `wl-copy` on stdin, never as an argument.

use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::Duration;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::Result;

pub const CLEAR_AFTER_SECS: u64 = 30;

pub fn copy_and_clear_later(secret: &[u8]) -> Result<()> {
    let mut wl_copy = Command::new("wl-copy")
        .args(["--type", "text/plain"])
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run wl-copy (package wl-clipboard): {e}"))?;
    let mut stdin = wl_copy.stdin.take().expect("stdin is piped");
    stdin.write_all(secret)?;
    drop(stdin);
    if !wl_copy.wait()?.success() {
        return Err("wl-copy failed".into());
    }

    let mut clearer = Command::new(std::env::current_exe()?)
        .args(["__clear-clipboard", &CLEAR_AFTER_SECS.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        // Its own process group: Ctrl-C in this terminal must not kill it.
        .process_group(0)
        .spawn()?;
    let mut stdin = clearer.stdin.take().expect("stdin is piped");
    stdin.write_all(&Sha256::digest(secret))?;
    Ok(())
}

/// Body of `__clear-clipboard`: runs detached, after the parent has exited.
pub fn clear_later(after_secs: u64) -> Result<()> {
    let mut expected = [0u8; 32];
    std::io::stdin().read_exact(&mut expected)?;
    std::thread::sleep(Duration::from_secs(after_secs));

    let output = Command::new("wl-paste")
        .args(["--no-newline", "--type", "text/plain"])
        .stderr(Stdio::null())
        .output()?;
    let current = Zeroizing::new(output.stdout);
    if output.status.success() && Sha256::digest(&*current)[..] == expected[..] {
        Command::new("wl-copy").arg("--clear").status()?;
    }
    Ok(())
}
