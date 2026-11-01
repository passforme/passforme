//! Reading secrets and confirmations from the user.
//!
//! On a terminal, secrets are read from `/dev/tty` without echo. When stdin
//! is not a terminal (a pipe, a test), each prompt reads one line from it
//! instead, like `sudo -S`, so secrets never have to be passed as arguments
//! or environment variables, where `ps` and `/proc` would show them.

use std::io::{self, BufRead, IsTerminal, Read, Write};

use secrecy::SecretString;
use zeroize::Zeroizing;

use crate::error::Result;

pub fn secret(prompt: &str) -> Result<SecretString> {
    if io::stdin().is_terminal() {
        return Ok(SecretString::from(rpassword::prompt_password(prompt)?));
    }
    eprint!("{prompt}");
    let line = read_line()?;
    eprintln!();
    Ok(SecretString::from(line.as_str()))
}

/// A visible answer, e.g. a confirmation.
pub fn line(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    Ok(read_line()?.to_string())
}

/// Several lines, up to end of input (Ctrl-D on a terminal).
pub fn multiline(prompt: &str) -> Result<Zeroizing<String>> {
    eprintln!("{prompt}");
    let mut text = Zeroizing::new(String::new());
    io::stdin().lock().read_to_string(&mut text)?;
    Ok(text)
}

fn read_line() -> Result<Zeroizing<String>> {
    let mut line = Zeroizing::new(String::new());
    io::stdin().lock().read_line(&mut line)?;
    let len = line.trim_end_matches(['\r', '\n']).len();
    line.truncate(len);
    Ok(line)
}
