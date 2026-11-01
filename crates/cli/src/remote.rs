//! The sync server, from the client side (`passforme_core::api`).
//!
//! HTTPS only (rustls with the Mozilla roots, which cover the Let's Encrypt
//! certificates of `tailscale serve`); plain HTTP is accepted for
//! `localhost`/`127.0.0.1` alone, for testing a server on this machine.

use std::time::Duration;

use base64ct::{Base64, Encoding};
use passforme_core::api::{self, ApiError, Prelogin, PutVault, Register, Revision, VaultResponse};
use passforme_core::kdf::AuthKey;
use serde::Serialize;
use serde::de::DeserializeOwned;
use ureq::Agent;
use zeroize::Zeroizing;

use crate::error::Result;

/// Larger than any vault the server accepts.
const BODY_LIMIT: u64 = 64 << 20;

pub struct Remote {
    base: String,
    agent: Agent,
}

pub enum Put {
    Stored(u64),
    /// Someone else uploaded first.
    Stale,
}

pub enum Fetch {
    Vault(VaultResponse),
    /// The auth key was refused: the master password changed elsewhere.
    Unauthorized,
}

impl Remote {
    pub fn new(url: &str) -> Result<Self> {
        let base = url.trim_end_matches('/').to_owned();
        let local = ["http://localhost:", "http://127.0.0.1:", "http://[::1]:"]
            .iter()
            .any(|p| base.starts_with(p));
        if !base.starts_with("https://") && !local {
            return Err(format!("{url}: the server must be reached over https://").into());
        }
        let agent = Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(60)))
            .build()
            .into();
        Ok(Self { base, agent })
    }

    pub fn url(&self) -> &str {
        &self.base
    }

    pub fn prelogin(&self) -> Result<Prelogin> {
        let response = self.agent.get(self.at(api::PRELOGIN)).call();
        let (status, body) = self.read(response)?;
        match status {
            200 => parse(&body),
            404 => Err(format!("{}: no account on this server yet", self.base).into()),
            _ => Err(self.failure(status, &body)),
        }
    }

    pub fn register(&self, request: &Register) -> Result<u64> {
        let (status, body) = self.send_json("POST", api::REGISTER, None, request)?;
        match status {
            200 => Ok(parse::<Revision>(&body)?.revision),
            _ => Err(self.failure(status, &body)),
        }
    }

    pub fn get_vault(&self, auth: &AuthKey) -> Result<Fetch> {
        let header = bearer(auth);
        let response = self
            .agent
            .get(self.at(api::VAULT))
            .header("Authorization", header.as_str())
            .call();
        let (status, body) = self.read(response)?;
        match status {
            200 => Ok(Fetch::Vault(parse(&body)?)),
            401 => Ok(Fetch::Unauthorized),
            _ => Err(self.failure(status, &body)),
        }
    }

    pub fn put_vault(&self, auth: &AuthKey, request: &PutVault) -> Result<Put> {
        let (status, body) = self.send_json("PUT", api::VAULT, Some(auth), request)?;
        match status {
            200 => Ok(Put::Stored(parse::<Revision>(&body)?.revision)),
            409 => Ok(Put::Stale),
            _ => Err(self.failure(status, &body)),
        }
    }

    fn at(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    fn send_json<T: Serialize>(
        &self,
        method: &str,
        path: &str,
        auth: Option<&AuthKey>,
        request: &T,
    ) -> Result<(u16, String)> {
        let body = Zeroizing::new(serde_json::to_vec(request).expect("requests serialize"));
        let url = self.at(path);
        let builder = match method {
            "POST" => self.agent.post(&url),
            _ => self.agent.put(&url),
        };
        let builder = builder.header("Content-Type", "application/json");
        let response = match auth {
            Some(auth) => builder
                .header("Authorization", bearer(auth).as_str())
                .send(&body[..]),
            None => builder.send(&body[..]),
        };
        self.read(response)
    }

    fn read(
        &self,
        response: std::result::Result<ureq::http::Response<ureq::Body>, ureq::Error>,
    ) -> Result<(u16, String)> {
        let mut response = response.map_err(|e| format!("cannot reach {}: {e}", self.base))?;
        let status = response.status().as_u16();
        let body = response
            .body_mut()
            .with_config()
            .limit(BODY_LIMIT)
            .read_to_string()
            .map_err(|e| format!("{}: {e}", self.base))?;
        Ok((status, body))
    }

    fn failure(&self, status: u16, body: &str) -> crate::error::Error {
        let message = serde_json::from_str::<ApiError>(body)
            .map_or_else(|_| format!("HTTP {status}"), |e| e.error);
        format!("{}: {message}", self.base).into()
    }
}

fn bearer(auth: &AuthKey) -> Zeroizing<String> {
    Zeroizing::new(format!(
        "Bearer {}",
        Base64::encode_string(auth.to_server())
    ))
}

fn parse<T: DeserializeOwned>(body: &str) -> Result<T> {
    serde_json::from_str(body).map_err(|e| format!("unexpected answer from the server: {e}").into())
}
