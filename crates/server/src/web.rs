//! HTTP routes (see `passforme_core::api` for the contract).

use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, State as AxumState};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64ct::{Base64, Encoding};
use passforme_core::api::{self, ApiError, Prelogin, PutVault, Register, Revision, VaultResponse};
use passforme_core::vault::VaultFile;
use tokio::sync::Mutex;

use crate::storage::{State, Storage};

/// A vault holds at most a few thousand items of 1 MiB each in theory; in
/// practice a few MiB. Anything bigger is refused before it is parsed.
const BODY_LIMIT: usize = 64 << 20;

pub struct App {
    /// One lock for everything: requests are rare and tiny, and it makes
    /// every read-modify-write of the revision atomic.
    pub storage: Mutex<Storage>,
}

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route(api::PRELOGIN, get(prelogin))
        .route(api::REGISTER, axum::routing::post(register))
        .route(api::VAULT, get(get_vault).put(put_vault))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .with_state(app)
}

fn error(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(ApiError {
            error: message.to_owned(),
        }),
    )
        .into_response()
}

fn internal(e: &std::io::Error) -> Response {
    eprintln!("passforme-server: storage error: {e}");
    error(StatusCode::INTERNAL_SERVER_ERROR, "storage error")
}

fn decode_key(text: &str) -> Option<[u8; 32]> {
    Base64::decode_vec(text).ok()?.try_into().ok()
}

/// Checks `Authorization: Bearer <auth key>` against the stored hash.
#[allow(clippy::result_large_err)] // a ready response is the axum idiom
fn authorize(headers: &HeaderMap, state: &State) -> Result<(), Response> {
    let given = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .and_then(decode_key);
    match (given, state.auth_hash()) {
        (Some(key), Some(stored)) if api::equal(&api::auth_hash(&key), &stored) => Ok(()),
        _ => {
            eprintln!("passforme-server: refused a request with a wrong or missing auth key");
            Err(error(StatusCode::UNAUTHORIZED, "wrong auth key"))
        }
    }
}

/// Parses an uploaded vault; it must be well formed and of this account.
#[allow(clippy::result_large_err)] // a ready response is the axum idiom
fn check_vault(text: &str, account_id: Option<&str>) -> Result<VaultFile, Response> {
    let file = VaultFile::from_json(text.as_bytes())
        .map_err(|e| error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let id = Base64::encode_string(file.account_id.as_bytes());
    if account_id.is_some_and(|expected| expected != id) {
        return Err(error(StatusCode::BAD_REQUEST, "vault of another account"));
    }
    Ok(file)
}

async fn prelogin(AxumState(app): AxumState<Arc<App>>) -> Response {
    let storage = app.storage.lock().await;
    match storage.state() {
        Ok(None) => error(StatusCode::NOT_FOUND, "no account on this server"),
        Ok(Some(_)) => match storage.vault() {
            Ok(text) => match VaultFile::from_json(text.as_bytes()) {
                Ok(file) => Json(Prelogin::from_file(&file)).into_response(),
                Err(e) => {
                    eprintln!("passforme-server: stored vault unreadable: {e}");
                    error(StatusCode::INTERNAL_SERVER_ERROR, "stored vault unreadable")
                }
            },
            Err(e) => internal(&e),
        },
        Err(e) => internal(&e),
    }
}

async fn register(AxumState(app): AxumState<Arc<App>>, Json(request): Json<Register>) -> Response {
    let storage = app.storage.lock().await;
    match storage.state() {
        Ok(Some(_)) => return error(StatusCode::CONFLICT, "this server already has an account"),
        Ok(None) => {}
        Err(e) => return internal(&e),
    }
    let Some(key) = decode_key(&request.auth_key) else {
        return error(StatusCode::BAD_REQUEST, "bad auth key");
    };
    let file = match check_vault(&request.vault, None) {
        Ok(file) => file,
        Err(response) => return response,
    };
    match storage.take_invite(&request.invite) {
        Ok(true) => {}
        Ok(false) => {
            eprintln!("passforme-server: refused a registration with a wrong or expired invite");
            return error(StatusCode::FORBIDDEN, "wrong or expired invite");
        }
        Err(e) => return internal(&e),
    }
    let state = State {
        revision: 1,
        account_id: Base64::encode_string(file.account_id.as_bytes()),
        auth_hash: Base64::encode_string(&api::auth_hash(&key)),
    };
    if let Err(e) = storage.commit(&request.vault, &state) {
        return internal(&e);
    }
    eprintln!("passforme-server: account registered");
    Json(Revision { revision: 1 }).into_response()
}

async fn get_vault(AxumState(app): AxumState<Arc<App>>, headers: HeaderMap) -> Response {
    let storage = app.storage.lock().await;
    let state = match storage.state() {
        Ok(Some(state)) => state,
        Ok(None) => return error(StatusCode::NOT_FOUND, "no account on this server"),
        Err(e) => return internal(&e),
    };
    if let Err(response) = authorize(&headers, &state) {
        return response;
    }
    match storage.vault() {
        Ok(vault) => Json(VaultResponse {
            revision: state.revision,
            vault,
        })
        .into_response(),
        Err(e) => internal(&e),
    }
}

async fn put_vault(
    AxumState(app): AxumState<Arc<App>>,
    headers: HeaderMap,
    Json(request): Json<PutVault>,
) -> Response {
    let storage = app.storage.lock().await;
    let state = match storage.state() {
        Ok(Some(state)) => state,
        Ok(None) => return error(StatusCode::NOT_FOUND, "no account on this server"),
        Err(e) => return internal(&e),
    };
    if let Err(response) = authorize(&headers, &state) {
        return response;
    }
    if request.base_revision != state.revision {
        return (
            StatusCode::CONFLICT,
            Json(Revision {
                revision: state.revision,
            }),
        )
            .into_response();
    }
    let file = match check_vault(&request.vault, Some(&state.account_id)) {
        Ok(file) => file,
        Err(response) => return response,
    };
    // A new salt means a new master password, hence a new auth key; without
    // it the client would lock itself out. The reverse makes no sense either.
    let current = match storage.vault().map(|t| VaultFile::from_json(t.as_bytes())) {
        Ok(Ok(current)) => current,
        Ok(Err(e)) => {
            eprintln!("passforme-server: stored vault unreadable: {e}");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "stored vault unreadable");
        }
        Err(e) => return internal(&e),
    };
    let salt_changed = file.salt != current.salt;
    let auth_hash = match (&request.new_auth_key, salt_changed) {
        (None, false) => state.auth_hash.clone(),
        (Some(key), true) => match decode_key(key) {
            Some(key) => Base64::encode_string(&api::auth_hash(&key)),
            None => return error(StatusCode::BAD_REQUEST, "bad auth key"),
        },
        (None, true) => {
            return error(
                StatusCode::BAD_REQUEST,
                "a new master password needs a new auth key",
            );
        }
        (Some(_), false) => {
            return error(
                StatusCode::BAD_REQUEST,
                "a new auth key needs a new master password",
            );
        }
    };
    let next = State {
        revision: state.revision + 1,
        account_id: state.account_id,
        auth_hash,
    };
    if let Err(e) = storage.commit(&request.vault, &next) {
        return internal(&e);
    }
    Json(Revision {
        revision: next.revision,
    })
    .into_response()
}
