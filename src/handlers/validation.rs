use crate::error::Error;
use serde::de::DeserializeOwned;

pub fn validate_json<T: DeserializeOwned>(data: &serde_json::Value) -> Result<T, Error> {
    serde_json::from_value(data.clone()).map_err(|_| Error::InvalidInput)
}
