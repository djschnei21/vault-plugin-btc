use crate::proto::plugin::{grpc_broker_server::GrpcBroker, ConnInfo};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, warn};

/// Implements the GRPCBroker service.
///
/// The host (Vault) connects to this service and advertises connection info
/// for services like Storage and SystemView. The plugin uses `dial_service`
/// to wait for and connect to a specific service by its broker ID.
#[derive(Clone)]
pub struct BrokerService {
    pending: Arc<Mutex<HashMap<u32, oneshot::Sender<ConnInfo>>>>,
}

impl BrokerService {
    pub fn new() -> Self {
        Self {
            pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Register interest in a service_id and wait for the host to advertise it.
    /// Returns the ConnInfo once the host sends it on the broker stream.
    pub async fn wait_for_service(&self, service_id: u32) -> Result<ConnInfo, String> {
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending.lock().await;
            pending.insert(service_id, tx);
        }
        rx.await.map_err(|e| format!("broker channel closed: {e}"))
    }
}

#[tonic::async_trait]
impl GrpcBroker for BrokerService {
    type StartStreamStream = ReceiverStream<Result<ConnInfo, Status>>;

    async fn start_stream(
        &self,
        request: Request<Streaming<ConnInfo>>,
    ) -> Result<Response<Self::StartStreamStream>, Status> {
        let mut inbound = request.into_inner();
        let pending = self.pending.clone();
        let (tx, rx) = mpsc::channel(16);

        tokio::spawn(async move {
            while let Ok(Some(info)) = inbound.message().await {
                debug!(
                    service_id = info.service_id,
                    network = %info.network,
                    address = %info.address,
                    "broker: received ConnInfo from host"
                );

                let mut map = pending.lock().await;
                if let Some(sender) = map.remove(&info.service_id) {
                    if sender.send(info).is_err() {
                        warn!("broker: receiver dropped for service");
                    }
                }
            }
            debug!("broker: inbound stream ended");
            drop(tx);
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}
