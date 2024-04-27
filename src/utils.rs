use argon2::Argon2;
use rand::{Rng, RngCore, rngs::OsRng};
use serde_json::{from_str, to_string};
use aes_gcm_siv::{aead::{Aead, KeyInit}, AeadCore, Aes256GcmSiv};
use base64::prelude::*;

use crate::constants::{KEY_BYTES, SALT_BYTES};
use crate::vault::Vault;

pub fn derive_key(password: &[u8], salt: &[u8]) -> [u8; KEY_BYTES] {
    let mut key = [0u8; KEY_BYTES];
    Argon2::default().hash_password_into(password, salt, &mut key).expect("\nKey Derivation Failed\n");
    key
}

pub fn generate_salt() -> [u8; SALT_BYTES] {
    let salt: [u8; SALT_BYTES] = OsRng.gen();
    salt
}

pub fn generate_random_id() -> u64 {
    OsRng.next_u64()
}

pub fn serialise_vault(vault: Vault) -> String {
    to_string(&vault).expect("\nSerialisation Failed\n")
}

pub fn deserialise_vault(json: String) -> Vault {
    let vault: Vault = from_str(&json).expect("\nDeserialisation Failed\n");
    vault
}

pub fn encrypt_string(input: &str, key: &[u8; KEY_BYTES]) -> String {
    let nonce = Aes256GcmSiv::generate_nonce(OsRng);
    let cipher = Aes256GcmSiv::new_from_slice(key).expect("\nInvalid Key Length\n");
    let ct = BASE64_STANDARD.encode(cipher.encrypt(&nonce, input.as_bytes()).expect("\nEncryption Failed\n"));
    ct
}