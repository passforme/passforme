//! The user's settings: `$XDG_CONFIG_HOME/passforme/config` (or
//! `~/.config/passforme/config`), `key = value` lines, `#` for comments.
//! A missing file means the defaults; an unknown key is an error, so a
//! typo never silently leaves a default in place.
//!
//! ```text
//! session = 15m    # how long the vault stays open unused; `off` asks every time
//! ```

use std::path::PathBuf;

use crate::error::Result;

pub struct Config {
    /// Idle seconds before the session locks; `None` turns sessions off.
    pub session_secs: Option<u64>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            session_secs: Some(crate::keeper::DEFAULT_IDLE_SECS),
        }
    }
}

fn path() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .map(|dir| dir.join("passforme").join("config"))
}

pub fn load() -> Result<Config> {
    let Some(path) = path() else {
        return Ok(Config::default());
    };
    match std::fs::read_to_string(&path) {
        Ok(text) => parse(&text).map_err(|e| format!("{}: {e}", path.display()).into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
        Err(e) => Err(crate::error::Error::Io(path, e)),
    }
}

fn parse(text: &str) -> std::result::Result<Config, String> {
    let mut config = Config::default();
    for (n, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("line {}: expected `key = value`", n + 1))?;
        match key.trim() {
            "session" => {
                let value = value.trim();
                config.session_secs = if value.eq_ignore_ascii_case("off") {
                    None
                } else {
                    match crate::parse_duration(value) {
                        Ok(Some(secs)) => Some(secs),
                        _ => {
                            return Err(format!(
                                "line {}: session must be like 15m, 1h or off",
                                n + 1
                            ));
                        }
                    }
                };
            }
            other => return Err(format!("line {}: unknown setting '{other}'", n + 1)),
        }
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_fifteen_minutes() {
        assert_eq!(parse("").unwrap().session_secs, Some(900));
        assert_eq!(parse("# nothing\n\n").unwrap().session_secs, Some(900));
    }

    #[test]
    fn reads_session() {
        assert_eq!(parse("session = 1h").unwrap().session_secs, Some(3600));
        assert_eq!(
            parse("session=30m # half an hour").unwrap().session_secs,
            Some(1800)
        );
        assert_eq!(parse("session = off").unwrap().session_secs, None);
    }

    #[test]
    fn rejects_typos_and_nonsense() {
        assert!(parse("sesion = 1h").is_err());
        assert!(parse("session = forever").is_err());
        assert!(parse("session = soon").is_err());
        assert!(parse("session").is_err());
    }
}
