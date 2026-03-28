pub mod paths;

use crate::error::Error;
use crate::handlers;
use crate::proto::pb::{Request as PbRequest, Response as PbResponse};
use crate::storage::Storage;
use paths::PathPattern;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tracing::debug;

/// The operation type extracted from the Vault request.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Operation {
    Create,
    Read,
    Update,
    Delete,
    List,
}

impl Operation {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "create" => Some(Operation::Create),
            "read" => Some(Operation::Read),
            "update" => Some(Operation::Update),
            "delete" => Some(Operation::Delete),
            "list" => Some(Operation::List),
            _ => None,
        }
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

/// Context passed to handler functions.
pub struct HandlerContext {
    pub params: HashMap<String, String>,
    pub data: serde_json::Value,
    pub storage: Arc<dyn Storage + Send + Sync>,
}

/// Type alias for async handler functions.
pub type HandlerFn = Arc<
    dyn Fn(HandlerContext) -> Pin<Box<dyn Future<Output = Result<PbResponse, Error>> + Send>>
        + Send
        + Sync,
>;

struct Route {
    pattern: PathPattern,
    handlers: HashMap<Operation, HandlerFn>,
}

/// Routes Vault requests to handler functions based on path and operation.
pub struct Router {
    routes: Vec<Route>,
}

impl Router {
    pub fn new() -> Self {
        let mut router = Self { routes: vec![] };
        handlers::register_routes(&mut router);
        router
    }

    /// Register a handler for a path pattern and operation.
    pub fn handle(
        &mut self,
        pattern: &str,
        operation: Operation,
        handler: impl Fn(HandlerContext) -> Pin<Box<dyn Future<Output = Result<PbResponse, Error>> + Send>>
            + Send
            + Sync
            + 'static,
    ) {
        let path_pattern = PathPattern::new(pattern);

        // Try to find an existing route with the same pattern string
        for route in &mut self.routes {
            // Simple check: see if they match the same test path
            // In practice, just add a new route each time
            if format!("{:?}", route.pattern) == format!("{:?}", path_pattern) {
                route.handlers.insert(operation, Arc::new(handler));
                return;
            }
        }

        let mut handlers = HashMap::new();
        handlers.insert(operation, Arc::new(handler) as HandlerFn);
        self.routes.push(Route {
            pattern: path_pattern,
            handlers,
        });
    }

    /// Route a Vault protobuf request to the appropriate handler.
    pub async fn route(
        &self,
        request: &PbRequest,
        storage: Arc<dyn Storage + Send + Sync>,
    ) -> Result<PbResponse, Error> {
        let operation = Operation::parse(&request.operation).ok_or_else(|| {
            Error::UnsupportedOperation(request.operation.clone(), request.path.clone())
        })?;

        let path = request.path.trim_matches('/');

        debug!(operation = ?operation, path = %path, "routing request");

        for route in &self.routes {
            // For list operations, only match list patterns
            if operation == Operation::List && !route.pattern.is_list_pattern() {
                continue;
            }
            if operation != Operation::List && route.pattern.is_list_pattern() {
                continue;
            }

            if let Some(params) = route.pattern.match_path(path) {
                if let Some(handler) = route.handlers.get(&operation) {
                    let data = if request.data.is_empty() {
                        serde_json::Value::Object(serde_json::Map::new())
                    } else {
                        serde_json::from_str(&request.data)
                            .unwrap_or_else(|_| serde_json::Value::Object(serde_json::Map::new()))
                    };

                    let ctx = HandlerContext {
                        params,
                        data,
                        storage: storage.clone(),
                    };

                    return handler(ctx).await;
                } else {
                    return Err(Error::UnsupportedOperation(
                        request.operation.clone(),
                        request.path.clone(),
                    ));
                }
            }
        }

        Err(Error::UnsupportedPath(request.path.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::super::proto::pb::Request as PbRequest;
    use super::super::storage::Storage;
    use super::Router;
    use crate::error::Error;
    use async_trait::async_trait;
    use std::sync::Arc;

    struct NoopStorage;

    #[async_trait]
    impl Storage for NoopStorage {
        async fn get(&self, _key: &str) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
            Ok(None)
        }

        async fn put(&self, _key: &str, _value: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }

        async fn delete(&self, _key: &str) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }

        async fn list(&self, _prefix: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
            Ok(vec![])
        }

        async fn put_sealed(
            &self,
            _key: &str,
            _value: Vec<u8>,
        ) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }
    }

    #[test]
    fn router_new_registers_routes() {
        let router = Router::new();

        assert!(!router.routes.is_empty());
    }

    #[tokio::test]
    async fn route_accepts_shared_router_reference() {
        let router = Router::new();
        let shared_router = &router;
        let request = PbRequest {
            operation: "read".to_string(),
            path: "missing".to_string(),
            ..Default::default()
        };

        let result = shared_router.route(&request, Arc::new(NoopStorage)).await;

        assert!(matches!(result, Err(Error::UnsupportedPath(path)) if path == "missing"));
    }
}
