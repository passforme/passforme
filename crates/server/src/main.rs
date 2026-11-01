use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tokio::sync::Mutex;

mod storage;
mod web;

use storage::Storage;

/// Sync server for passforme vaults. Stores ciphertext only: it holds no key
/// able to decrypt anything.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Data directory.
    #[arg(long, global = true, default_value = "/var/lib/passforme")]
    data: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the API. Meant for 127.0.0.1 behind HTTPS (`tailscale serve`), or
    /// 0.0.0.0 inside a container.
    Serve {
        #[arg(long, default_value = "127.0.0.1:8090")]
        listen: SocketAddr,
    },
    /// Print a single-use invite for `passforme register`, valid for 1 hour.
    Invite,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Serve { listen } => serve(cli.data, listen),
        Command::Invite => invite(&cli.data),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("passforme-server: {e}");
            ExitCode::FAILURE
        }
    }
}

fn invite(data: &Path) -> Result<(), String> {
    let storage = Storage::new(data.to_path_buf());
    if storage.state().map_err(|e| e.to_string())?.is_some() {
        return Err("this server already has an account".into());
    }
    let token = storage
        .create_invite()
        .map_err(|e| format!("{}: {e}", data.display()))?;
    println!("{token}");
    eprintln!("Single-use invite, valid for 1 hour: `passforme register URL` asks for it.");
    Ok(())
}

fn serve(data: PathBuf, listen: SocketAddr) -> Result<(), String> {
    if !data.is_dir() {
        return Err(format!("{} is not a directory", data.display()));
    }
    let app = Arc::new(web::App {
        storage: Mutex::new(Storage::new(data)),
    });
    let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(listen)
            .await
            .map_err(|e| format!("cannot listen on {listen}: {e}"))?;
        eprintln!("passforme-server: listening on http://{listen}");
        axum::serve(listener, web::router(app))
            .with_graceful_shutdown(shutdown())
            .await
            .map_err(|e| e.to_string())
    })
}

async fn shutdown() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}
