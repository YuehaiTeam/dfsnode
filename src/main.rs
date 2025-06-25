use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

mod app;
mod autoindex;
mod cache;
mod config;
mod handlers;
mod metrics;
mod response;
mod signature;

use app::{AppState, parse_central_url};
use config::{config_refresh_task, load_config_from_central, load_config_from_file};
use handlers::handle_request;
use metrics::{ACTIVE_CONNECTIONS, register_metrics};

// Connection pool to limit concurrent connections
const MAX_CONNECTIONS: usize = 2048;

#[derive(Parser, Debug)]
#[command(name = "dfsnode")]
struct Args {
    /// Central server URL with authentication
    #[arg(long)]
    central: Option<String>,

    /// Configuration file path
    #[arg(long)]
    config: Option<String>,

    /// File storage directory
    #[arg(long, default_value = "./data")]
    dir: String,

    /// Port to listen on
    #[arg(long, default_value = "8093")]
    port: u16,

    /// BitTorrent port to listen on (0 for random port)
    #[arg(long, default_value = "0")]
    bt_port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing with env-filter support
    // Can be controlled via RUST_LOG environment variable
    // Example: RUST_LOG=info,dfsnode=debug
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Register metrics
    register_metrics()?;

    let args = Args::parse();

    // Validate arguments
    if args.central.is_some() && args.config.is_some() {
        anyhow::bail!("Cannot specify both --central and --config");
    }

    if args.central.is_none() && args.config.is_none() {
        anyhow::bail!("Must specify either --central or --config");
    }

    let data_dir = PathBuf::from(&args.dir);
    tokio::fs::create_dir_all(&data_dir).await?;

    let (central_url, auth_header, server_id) = if let Some(central) = args.central {
        parse_central_url(&central)?
    } else {
        (None, None, None)
    };

    let bt_session = librqbit::Session::new_with_opts(
        std::env::temp_dir(),
        librqbit::SessionOptions {
            disable_dht: true,
            listen: Some(librqbit::ListenerOptions {
                mode: librqbit::ListenerMode::TcpAndUtp,
                listen_addr: std::net::SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], args.bt_port)),
                enable_upnp_port_forwarding: false,
                utp_opts: None,
            }),
            ..Default::default()
        },
    )
    .await
    .context("Failed to create BitTorrent session")?;

    let state = AppState::new(data_dir, central_url, auth_header, server_id, bt_session);

    // Load initial config
    if let Some(config_path) = args.config {
        load_config_from_file(&state.config, &config_path, &state).await?;
    } else {
        load_config_from_central(
            &state.config,
            state.central_url.as_ref().unwrap(),
            state.server_id.as_deref(),
            state.auth_header.as_deref(),
            &state.http_client,
            &state,
        )
        .await?;
    }

    // Start config refresh task if using central server
    if state.central_url.is_some() {
        let config_clone = state.config.clone();
        let central_url = state.central_url.clone().unwrap();
        let server_id = state.server_id.clone();
        let auth_header = state.auth_header.clone();
        let http_client = state.http_client.clone();
        let state_cl = state.clone();
        tokio::spawn(async move {
            config_refresh_task(
                config_clone,
                central_url,
                server_id,
                auth_header,
                http_client,
                &state_cl,
            )
            .await;
        });
    }

    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));
    let listener = TcpListener::bind(addr).await?;

    info!("Gateway listening on {}", addr);

    // Semaphore to limit concurrent connections
    let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    loop {
        let (stream, _) = listener.accept().await?;

        // Acquire semaphore permit
        let permit = match semaphore.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => {
                warn!("Failed to acquire connection permit, dropping connection");
                continue;
            }
        };

        let io = TokioIo::new(stream);
        let state = state.clone();

        ACTIVE_CONNECTIONS.inc();

        tokio::task::spawn(async move {
            let _permit = permit; // Hold permit for connection lifetime

            let result = hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    io,
                    hyper::service::service_fn(move |req| handle_request(state.clone(), req)),
                )
                .await;

            ACTIVE_CONNECTIONS.dec();

            if let Err(err) = result {
                error!("Error serving connection: {:?}", err);
            }
        });
    }
}
