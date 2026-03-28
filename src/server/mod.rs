pub mod backend_service;
pub mod broker_service;
pub mod controller_service;
pub mod stdio_service;

use crate::proto::pb::backend_server::BackendServer;
use crate::proto::plugin::grpc_broker_server::GrpcBrokerServer;
use crate::proto::plugin::grpc_controller_server::GrpcControllerServer;
use crate::proto::plugin::grpc_stdio_server::GrpcStdioServer;
use crate::router::Router;
use backend_service::BackendService;
use broker_service::BrokerService;
use controller_service::ControllerService;
use stdio_service::StdioService;

use base64::Engine;
use rcgen::{CertificateParams, KeyPair};
use std::io::Write;
use std::net::TcpListener;
use std::sync::Arc;
use tokio::sync::watch;
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tracing::{error, info};

/// The magic cookie key and value that Vault uses to validate the plugin.
const MAGIC_COOKIE_KEY: &str = "VAULT_BACKEND_PLUGIN";
const MAGIC_COOKIE_VALUE: &str = "6669da05-b1c8-4f49-97d9-c8e5bed98e20";

/// Core protocol version (always 1).
const CORE_PROTOCOL_VERSION: u32 = 1;

/// App protocol version for Vault plugins.
const APP_PROTOCOL_VERSION: u32 = 5;

/// Start the plugin server: validate magic cookie, set up TLS, bind port,
/// print handshake, and serve gRPC.
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Validate magic cookie
    let cookie = std::env::var(MAGIC_COOKIE_KEY).unwrap_or_default();
    if cookie != MAGIC_COOKIE_VALUE {
        eprintln!(
            "This binary is a plugin. These are not meant to be executed directly.\n\
             Please execute the program that consumes these plugins, which will\n\
             load any plugins automatically."
        );
        std::process::exit(1);
    }

    // 2. Generate TLS certificate
    let key_pair = KeyPair::generate()?;
    let cert_params = CertificateParams::new(vec!["localhost".to_string()])?;
    let cert = cert_params.self_signed(&key_pair)?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    let server_cert_der = cert.der().to_vec();

    // Build server TLS config
    let mut tls_config = ServerTlsConfig::new().identity(Identity::from_pem(&cert_pem, &key_pem));

    // If AutoMTLS: the host provides its client cert, and we verify it
    if let Ok(client_cert_b64) = std::env::var("PLUGIN_CLIENT_CERT") {
        let client_cert_pem = String::from_utf8(
            base64::engine::general_purpose::STANDARD.decode(&client_cert_b64)?,
        )?;
        let client_ca = tonic::transport::Certificate::from_pem(&client_cert_pem);
        tls_config = tls_config.client_ca_root(client_ca);
    }

    // 3. Bind ephemeral port
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let local_addr = listener.local_addr()?;

    // 4. Create services
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

    let broker = Arc::new(BrokerService::new());
    let router = Router::new();
    let backend = BackendService::new(broker.clone(), router);

    let controller = ControllerService::new(shutdown_tx);
    let stdio = StdioService::empty();

    // 5. Print handshake line to stdout
    let cert_b64 =
        base64::engine::general_purpose::STANDARD.encode(&server_cert_der);

    let handshake = format!(
        "{}|{}|tcp|{}|grpc|{}",
        CORE_PROTOCOL_VERSION, APP_PROTOCOL_VERSION, local_addr, cert_b64
    );

    // Write handshake to stdout and flush immediately
    {
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        writeln!(handle, "{}", handshake)?;
        handle.flush()?;
    }

    info!(address = %local_addr, "plugin server starting");

    // 6. Build and serve
    let incoming = tokio::net::TcpListener::from_std(listener)?;
    let incoming_stream = tokio_stream::wrappers::TcpListenerStream::new(incoming);

    // Build health service
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<BackendServer<BackendService>>()
        .await;

    let server = Server::builder()
        .tls_config(tls_config)?
        .add_service(health_service)
        .add_service(BackendServer::new(backend))
        .add_service(GrpcBrokerServer::new((*broker).clone()))
        .add_service(GrpcControllerServer::new(controller))
        .add_service(GrpcStdioServer::new(stdio));

    // Serve until shutdown
    let graceful = server.serve_with_incoming_shutdown(incoming_stream, async move {
        shutdown_rx.changed().await.ok();
        info!("shutting down plugin server");
    });

    if let Err(e) = graceful.await {
        error!(error = %e, "server error");
        return Err(e.into());
    }

    Ok(())
}
