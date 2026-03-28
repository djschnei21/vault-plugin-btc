use crate::proto::pb;
use crate::proto::pb::{
    backend_server::Backend, SetupArgs, SetupReply, InitializeArgs, InitializeReply, TypeReply, SpecialPathsReply, Paths, HandleRequestArgs, HandleRequestReply, HandleExistenceCheckArgs, HandleExistenceCheckReply, InvalidateKeyArgs,
    storage_client::StorageClient,
};
use crate::proto::plugin::Empty;
use crate::router::Router;
use crate::server::broker_service::BrokerService;
use crate::storage::{Storage, VaultStorage};
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::transport::Channel;
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};

/// The core Vault Backend service implementation.
///
/// Routes incoming HandleRequest calls to the appropriate handler
/// based on path and operation, using Vault's storage via the broker.
pub struct BackendService {
    storage: Arc<RwLock<Option<VaultStorage>>>,
    broker: Arc<BrokerService>,
    router: Arc<Router>,
}

impl BackendService {
    pub fn new(broker: Arc<BrokerService>, router: Router) -> Self {
        Self {
            storage: Arc::new(RwLock::new(None)),
            broker,
            router: Arc::new(router),
        }
    }

    async fn get_storage(&self) -> Result<VaultStorage, Status> {
        let guard = self.storage.read().await;
        guard
            .clone()
            .ok_or_else(|| Status::unavailable("storage not initialized - Setup not called"))
    }
}

#[tonic::async_trait]
impl Backend for BackendService {
    /// Setup is called by Vault after the plugin starts.
    /// It provides a broker_id that we use to connect back to Vault's Storage service.
    async fn setup(&self, request: Request<SetupArgs>) -> Result<Response<SetupReply>, Status> {
        let args = request.into_inner();
        let broker_id = args.broker_id;

        info!(broker_id, "setting up backend");

        // Wait for the host to advertise the storage service via the broker
        let conn_info = self
            .broker
            .wait_for_service(broker_id)
            .await
            .map_err(|e| Status::internal(format!("broker dial failed: {e}")))?;

        info!(
            address = %conn_info.address,
            network = %conn_info.network,
            "connecting to vault storage service"
        );

        // Connect to the advertised storage service
        let endpoint = format!("http://{}", conn_info.address);
        let channel = Channel::from_shared(endpoint)
            .map_err(|e| Status::internal(format!("invalid endpoint: {e}")))?
            .connect()
            .await
            .map_err(|e| Status::internal(format!("failed to connect to storage: {e}")))?;

        let storage_client = StorageClient::new(channel);
        let vault_storage = VaultStorage::new(storage_client);

        {
            let mut guard = self.storage.write().await;
            *guard = Some(vault_storage);
        }

        info!("backend setup complete");

        Ok(Response::new(SetupReply {
            err: String::new(),
        }))
    }

    /// Initialize is called after Setup to perform any post-mount initialization.
    async fn initialize(
        &self,
        _request: Request<InitializeArgs>,
    ) -> Result<Response<InitializeReply>, Status> {
        info!("backend initialized");
        Ok(Response::new(InitializeReply { err: None }))
    }

    /// Type returns the backend type (1 = secret engine).
    async fn r#type(&self, _request: Request<Empty>) -> Result<Response<TypeReply>, Status> {
        Ok(Response::new(TypeReply { r#type: 1 }))
    }

    /// SpecialPaths returns paths that have special access requirements.
    async fn special_paths(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<SpecialPathsReply>, Status> {
        Ok(Response::new(SpecialPathsReply {
            paths: Some(Paths {
                root: vec!["config".to_string()],
                unauthenticated: vec![],
                local_storage: vec![],
                seal_wrap_storage: vec!["wallets/+/secrets".to_string()],
                write_forwarded_storage: vec![],
                binary: vec![],
                limited: vec![],
                allow_snapshot_read: vec![],
            }),
        }))
    }

    /// HandleRequest is the main dispatch point for all API requests.
    async fn handle_request(
        &self,
        request: Request<HandleRequestArgs>,
    ) -> Result<Response<HandleRequestReply>, Status> {
        let args = request.into_inner();
        let storage = self.get_storage().await?;

        let pb_request = match args.request {
            Some(req) => req,
            None => {
                return Ok(Response::new(HandleRequestReply {
                    response: None,
                    err: Some(
                        Error::InvalidRequest("missing request".to_string()).to_proto_error(),
                    ),
                    wal_index: None,
                }));
            }
        };

        let operation = pb_request.operation.clone();
        let path = pb_request.path.clone();

        debug!(operation = %operation, path = %path, "handling request");

        match self.router.route(&pb_request, Arc::new(storage) as Arc<dyn Storage + Send + Sync>).await {
            Ok(response) => Ok(Response::new(HandleRequestReply {
                response: Some(response),
                err: None,
                wal_index: None,
            })),
            Err(e) => {
                warn!(error = %e, path = %path, "request failed");
                Ok(Response::new(HandleRequestReply {
                    response: None,
                    err: Some(e.to_proto_error()),
                    wal_index: None,
                }))
            }
        }
    }

    /// HandleExistenceCheck checks if a resource exists at the given path.
    async fn handle_existence_check(
        &self,
        request: Request<HandleExistenceCheckArgs>,
    ) -> Result<Response<HandleExistenceCheckReply>, Status> {
        let args = request.into_inner();
        let storage = self.get_storage().await?;

        let pb_request = match args.request {
            Some(req) => req,
            None => {
                return Ok(Response::new(HandleExistenceCheckReply {
                    check_found: false,
                    exists: false,
                    err: None,
                }));
            }
        };

        let path = &pb_request.path;

        // Check if a wallet exists at this path
        if path.starts_with("wallets/") {
            let parts: Vec<&str> = path.split('/').collect();
            if parts.len() == 2 && !parts[1].is_empty() {
                let key = format!("wallets/{}/metadata", parts[1]);
                match storage.get(&key).await {
                    Ok(Some(_)) => {
                        return Ok(Response::new(HandleExistenceCheckReply {
                            check_found: true,
                            exists: true,
                            err: None,
                        }));
                    }
                    Ok(None) => {
                        return Ok(Response::new(HandleExistenceCheckReply {
                            check_found: true,
                            exists: false,
                            err: None,
                        }));
                    }
                    Err(e) => {
                        let proto_err = if let Ok(err) = e.downcast::<Error>() {
                            err.to_proto_error()
                        } else {
                            pb::ProtoError {
                                err_type: 2,
                                err_msg: e.to_string(),
                                err_code: 500,
                            }
                        };
                        return Ok(Response::new(HandleExistenceCheckReply {
                            check_found: false,
                            exists: false,
                            err: Some(proto_err),
                        }));
                    }
                }
            }
        }

        Ok(Response::new(HandleExistenceCheckReply {
            check_found: false,
            exists: false,
            err: None,
        }))
    }

    /// Cleanup is called when the backend is being unmounted.
    async fn cleanup(&self, _request: Request<Empty>) -> Result<Response<Empty>, Status> {
        info!("backend cleanup");
        let mut guard = self.storage.write().await;
        *guard = None;
        Ok(Response::new(Empty {}))
    }

    /// InvalidateKey is called when a storage key is modified externally.
    async fn invalidate_key(
        &self,
        request: Request<InvalidateKeyArgs>,
    ) -> Result<Response<Empty>, Status> {
        let args = request.into_inner();
        debug!(key = %args.key, "invalidating key");
        Ok(Response::new(Empty {}))
    }
}
