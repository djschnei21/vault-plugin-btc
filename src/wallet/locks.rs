use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use tokio::sync::Mutex;

fn registry() -> &'static Mutex<HashMap<String, Arc<Mutex<()>>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, Arc<Mutex<()>>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

pub async fn wallet_lock(name: &str) -> Arc<Mutex<()>> {
    let mut registry = registry().lock().await;
    registry
        .entry(name.to_string())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}
