use crate::proto::plugin::{grpc_controller_server::GrpcController, Empty};
use tokio::sync::watch;
use tonic::{Request, Response, Status};
use tracing::info;

/// Implements the GRPCController service.
/// Vault calls Shutdown when the plugin should exit.
pub struct ControllerService {
    shutdown_tx: watch::Sender<bool>,
}

impl ControllerService {
    pub fn new(shutdown_tx: watch::Sender<bool>) -> Self {
        Self { shutdown_tx }
    }
}

#[tonic::async_trait]
impl GrpcController for ControllerService {
    async fn shutdown(&self, _request: Request<Empty>) -> Result<Response<Empty>, Status> {
        info!("received shutdown request from vault");
        let _ = self.shutdown_tx.send(true);
        Ok(Response::new(Empty {}))
    }
}
