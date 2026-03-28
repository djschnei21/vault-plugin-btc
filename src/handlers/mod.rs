pub mod addresses;
pub mod config;
pub mod keys;
pub mod psbt;
pub mod sign;
pub mod wallets;

use crate::proto::pb::Response as PbResponse;
use crate::router::{Operation, Router};

/// Helper to build a successful Vault response with JSON data.
pub fn ok_response(data: serde_json::Value) -> PbResponse {
    PbResponse {
        secret: None,
        auth: None,
        data: serde_json::to_string(&data).unwrap_or_default(),
        redirect: String::new(),
        warnings: vec![],
        wrap_info: None,
        headers: Default::default(),
        mount_type: String::new(),
    }
}

/// Helper to build a Vault list response.
pub fn list_response(keys: Vec<String>) -> PbResponse {
    let data = serde_json::json!({ "keys": keys });
    ok_response(data)
}

/// Helper to build an empty successful response.
pub fn empty_response() -> PbResponse {
    PbResponse {
        secret: None,
        auth: None,
        data: String::new(),
        redirect: String::new(),
        warnings: vec![],
        wrap_info: None,
        headers: Default::default(),
        mount_type: String::new(),
    }
}

/// Register all handler routes.
pub fn register_routes(router: &mut Router) {
    // Config
    router.handle("config", Operation::Read, |ctx| {
        Box::pin(config::read_config(ctx))
    });
    router.handle("config", Operation::Update, |ctx| {
        Box::pin(config::write_config(ctx))
    });

    // Wallets
    router.handle("wallets/?", Operation::List, |ctx| {
        Box::pin(wallets::list_wallets(ctx))
    });
    router.handle("wallets/:name", Operation::Create, |ctx| {
        Box::pin(wallets::create_wallet(ctx))
    });
    router.handle("wallets/:name", Operation::Read, |ctx| {
        Box::pin(wallets::read_wallet(ctx))
    });
    router.handle("wallets/:name", Operation::Update, |ctx| {
        Box::pin(wallets::create_wallet(ctx))
    });
    router.handle("wallets/:name", Operation::Delete, |ctx| {
        Box::pin(wallets::delete_wallet(ctx))
    });

    // Keys
    router.handle("wallets/:name/keys", Operation::Read, |ctx| {
        Box::pin(keys::get_keys(ctx))
    });
    router.handle("wallets/:name/keys/derive", Operation::Update, |ctx| {
        Box::pin(keys::derive_key(ctx))
    });

    // Addresses
    router.handle("wallets/:name/addresses/new", Operation::Update, |ctx| {
        Box::pin(addresses::new_address(ctx))
    });
    router.handle("wallets/:name/addresses", Operation::Read, |ctx| {
        Box::pin(addresses::list_addresses(ctx))
    });

    // Signing
    router.handle("wallets/:name/sign", Operation::Update, |ctx| {
        Box::pin(sign::sign_psbt(ctx))
    });
    router.handle("wallets/:name/sign-raw", Operation::Update, |ctx| {
        Box::pin(sign::sign_raw(ctx))
    });

    // PSBT operations
    router.handle("psbt/create", Operation::Update, |ctx| {
        Box::pin(psbt::create_psbt(ctx))
    });
    router.handle("psbt/combine", Operation::Update, |ctx| {
        Box::pin(psbt::combine_psbt(ctx))
    });
    router.handle("psbt/finalize", Operation::Update, |ctx| {
        Box::pin(psbt::finalize_psbt(ctx))
    });
    router.handle("psbt/decode", Operation::Update, |ctx| {
        Box::pin(psbt::decode_psbt(ctx))
    });
}
