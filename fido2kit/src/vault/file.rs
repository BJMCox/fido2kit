//! The vault file layouts as written, before validation. Byte fields are standard base64.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Version 1: one password, which loads as the `ANY` entry.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct V1 {
    #[allow(dead_code)]
    pub version: u32,
    #[serde(with = "b64")]
    pub salt: Vec<u8>,
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
    pub keys: Vec<KeyV2>,
}

/// Version 2, field for field as fido2kpxc wrote it, so a saved v2 vault keeps its bytes.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct V2 {
    pub version: u32,
    #[serde(with = "b64")]
    pub salt: Vec<u8>,
    pub keys: Vec<KeyV2>,
    pub secrets: Vec<SecretV2>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct KeyV2 {
    pub label: String,
    #[serde(with = "b64")]
    pub cred_id: Vec<u8>,
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "b64")]
    pub wrapped_key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SecretV2 {
    #[serde(rename = "database")]
    pub name: String,
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct V3 {
    pub version: u32,
    pub aead: String,
    pub kdf: String,
    pub mac: String,
    pub threshold: u8,
    pub generation: u64,
    #[serde(with = "b64")]
    pub tag: Vec<u8>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub meta: BTreeMap<String, String>,
    pub keys: Vec<KeyV3>,
    pub secrets: Vec<SecretV3>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct KeyV3 {
    pub kind: String,
    pub label: String,
    #[serde(with = "b64")]
    pub cred_id: Vec<u8>,
    #[serde(with = "b64")]
    pub salt: Vec<u8>,
    pub share: u8,
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "b64")]
    pub wrapped: Vec<u8>,
    #[serde(default, with = "b64_opt", skip_serializing_if = "Option::is_none")]
    pub aaguid: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uv: Option<bool>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub meta: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SecretV3 {
    pub name: String,
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
    #[serde(default, with = "b64_opt", skip_serializing_if = "Option::is_none")]
    pub pending_nonce: Option<Vec<u8>>,
    #[serde(default, with = "b64_opt", skip_serializing_if = "Option::is_none")]
    pub pending_ciphertext: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub meta: BTreeMap<String, String>,
}

mod b64 {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        STANDARD.decode(text).map_err(serde::de::Error::custom)
    }
}

mod b64_opt {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        bytes: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(bytes) => super::b64::serialize(bytes, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        super::b64::deserialize(deserializer).map(Some)
    }
}
