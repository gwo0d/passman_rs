use argon2::Argon2;
use rand::{RngCore, rngs::OsRng};
use serde_json::{from_str, to_string};

use crate::constants::{KEY_SIZE, SALT_SIZE};
use crate::vault::Vault;

pub fn derive_key(password: &[u8], salt: &[u8]) -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    Argon2::default().hash_password_into(password, salt, &mut key).expect("\nKey Derivation Failed\n");
    key
}

pub fn generate_salt() -> [u8; SALT_SIZE] {
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
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