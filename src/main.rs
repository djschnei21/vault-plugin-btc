use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    // Initialize tracing to stderr (stdout is reserved for the handshake protocol)
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    if let Err(e) = vault_plugin_btc::server::run().await {
        eprintln!("plugin error: {e}");
        std::process::exit(1);
    }
}
