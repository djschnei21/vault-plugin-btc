use tracing_subscriber::EnvFilter;

mod config;
mod error;
mod handlers;
mod proto;
mod router;
mod server;
mod storage;
mod wallet;

#[tokio::main]
async fn main() {
    // Initialize tracing to stderr (stdout is reserved for the handshake protocol)
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    if let Err(e) = server::run().await {
        eprintln!("plugin error: {e}");
        std::process::exit(1);
    }
}
