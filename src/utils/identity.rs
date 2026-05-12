use ic_agent::{identity::Secp256k1Identity, Identity};

use crate::kv::{
    dragonfly_kv::{format_to_dragonfly_key, KEY_PREFIX},
    KVError, KVStore, KVStoreImpl,
};

pub async fn generate_random_identity_and_save(
    kv: &KVStoreImpl,
) -> Result<Secp256k1Identity, KVError> {
    let key = k256::SecretKey::random(&mut rand::thread_rng());
    let base_jwk = key.to_jwk_string();
    let identity = Secp256k1Identity::from_private_key(key);
    let principal = identity.sender().unwrap();

    kv.write(
        format_to_dragonfly_key(KEY_PREFIX, &principal.to_text()),
        base_jwk.to_string(),
    )
    .await?;

    Ok(identity)
}
