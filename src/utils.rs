use argon2::Argon2;
use rand::{RngCore, rngs::OsRng};
use crate::constants::{KEY_SIZE, SALT_SIZE};

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