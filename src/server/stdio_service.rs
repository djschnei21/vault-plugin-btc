use crate::proto::plugin::{grpc_stdio_server::GrpcStdio, StdioData};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::debug;

/// Implements the GRPCStdio service.
///
/// After the handshake line is printed to stdout, Vault connects to this
/// service to consume any further stdout/stderr output from the plugin.
/// For a Rust plugin, we route tracing output through stderr and forward
/// it via this service.
pub struct StdioService {
    stderr_rx: tokio::sync::Mutex<Option<mpsc::Receiver<Vec<u8>>>>,
}

impl StdioService {
    pub fn new(stderr_rx: mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            stderr_rx: tokio::sync::Mutex::new(Some(stderr_rx)),
        }
    }

    /// Create a StdioService that sends no data (simplest implementation).
    pub fn empty() -> Self {
        let (_tx, rx) = mpsc::channel(1);
        Self {
            stderr_rx: tokio::sync::Mutex::new(Some(rx)),
        }
    }
}

#[tonic::async_trait]
impl GrpcStdio for StdioService {
    type StreamStdioStream = ReceiverStream<Result<StdioData, Status>>;

    async fn stream_stdio(
        &self,
        _request: Request<()>,
    ) -> Result<Response<Self::StreamStdioStream>, Status> {
        let (tx, rx) = mpsc::channel(64);

        // Take the stderr receiver (can only be called once)
        let stderr_rx = self.stderr_rx.lock().await.take();

        if let Some(mut stderr_rx) = stderr_rx {
            tokio::spawn(async move {
                while let Some(data) = stderr_rx.recv().await {
                    let msg = StdioData {
                        channel: 2, // STDERR
                        data,
                    };
                    if tx.send(Ok(msg)).await.is_err() {
                        break;
                    }
                }
                debug!("stdio stream ended");
            });
        }

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}
