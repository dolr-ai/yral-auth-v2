use ic_agent::{identity::Secp256k1Identity, Identity};

use crate::kv::{KVError, KVStore, KVStoreImpl};

pub async fn generate_random_identity_and_save(
    kv: &KVStoreImpl,
    dragonfly_kv: &KVStoreImpl
) -> Result<Secp256k1Identity, KVError> {
    let key = k256::SecretKey::random(&mut rand::thread_rng());
    let base_jwk = key.to_jwk_string();
    let identity = Secp256k1Identity::from_private_key(key);
    let principal = identity.sender().unwrap();

    kv.write(principal.to_text(), base_jwk.to_string()).await?;
    dragonfly_kv.write(principal.to_text(), base_jwk.to_string()).await?;

    Ok(identity)
}
