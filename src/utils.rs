use std::fs;
use std::io::{stdin, stdout, Write};
use std::path::Path;

use aes_gcm_siv::{aead::{Aead, KeyInit}, AeadCore, Aes256GcmSiv, Nonce};
use argon2::Argon2;
use base64::prelude::*;
use clearscreen::clear;
use rand::{Rng, RngCore, rngs::OsRng};
use serde_json::{from_str, to_string};

use crate::constants::{KEY_BYTES, SALT_BYTES, VAULT_DIRECTORY};
use crate::vault::Vault;

/// The `utils` module provides utility functions for the application.
/// It includes functions for key derivation, salt generation, random ID generation,
/// vault serialization and deserialization, vault encryption and decryption,
/// and file read/write operations.

/// Derives a key from the given password and salt using the Argon2 password hashing function.
/// Returns the derived key.
pub(crate) fn derive_key(password: &[u8], salt: &[u8]) -> [u8; KEY_BYTES] {
    let mut key = [0u8; KEY_BYTES];
    Argon2::default().hash_password_into(password, salt, &mut key).expect("\nKey Derivation Failed\n");
    key
}

/// Generates a random salt using the operating system's random number generator.
/// Returns the generated salt.
pub(crate) fn generate_salt() -> [u8; SALT_BYTES] {
    let salt: [u8; SALT_BYTES] = OsRng.gen();
    salt
}

/// Generates a random ID using the operating system's random number generator.
/// Returns the generated ID.
pub(crate) fn generate_random_id() -> u64 {
    OsRng.next_u64()
}

/// Serializes the given `Vault` into a JSON string.
/// Returns the serialized `Vault`.
fn serialise_vault(vault: &Vault) -> String {
    to_string(&vault).expect("\nSerialisation Failed\n")
}

/// Deserializes the given JSON string into a `Vault`.
/// Returns the deserialized `Vault`.
fn deserialise_vault(json: String) -> Vault {
    let vault: Vault = from_str(&json).expect("\nDeserialisation Failed\n");
    vault
}

/// Encrypts the given `Vault` using the AES-GCM-SIV encryption algorithm.
/// Returns the encrypted `Vault` as a string.
fn encrypt_vault(vault: &Vault) -> String {
    let vault_name = vault.get_vault_name();
    let key = vault.get_vault_key();
    let salt = BASE64_STANDARD.encode(vault.get_salt());
    let pt = serialise_vault(&vault);
    let nonce = Aes256GcmSiv::generate_nonce(OsRng);
    let cipher = Aes256GcmSiv::new_from_slice(key).expect("\nInvalid Key Length\n");
    let ct = BASE64_STANDARD.encode(cipher.encrypt(&nonce, pt.as_bytes()).expect("\nEncryption Failed\n"));
    let nonce = BASE64_STANDARD.encode(nonce);
    format!("{}:{}:{}:{}", vault_name, salt, nonce, ct)
}

/// Decrypts the given encrypted `Vault` string using the AES-GCM-SIV encryption algorithm.
/// Returns the decrypted `Vault`.
fn decrypt_vault(encrypted_vault_string: &str, password: &str) -> Vault {
    let mut split = encrypted_vault_string.split(':');
    split.next();
    let salt = BASE64_STANDARD.decode(split.next().expect("\nInvalid Vault String\n")).expect("\nInvalid Base64\n");
    let key = derive_key(password.as_bytes(), &salt);
    let nonce_bytes = BASE64_STANDARD.decode(split.next().expect("\nInvalid Vault String\n")).expect("\nInvalid Base64\n");
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = BASE64_STANDARD.decode(split.next().expect("\nInvalid Vault String\n")).expect("\nInvalid Base64\n");
    let cipher = Aes256GcmSiv::new_from_slice(&key).expect("\nInvalid Key Length\n");
    let pt = cipher.decrypt(&nonce, ct.as_ref()).expect("\nDecryption Failed\n");
    deserialise_vault(String::from_utf8(pt).expect("\nInvalid UTF-8\n"))
}

/// Saves the given string content to a file at the given file path.
fn save_string_to_file(file_path: &str, content: &str) {
    let path = Path::new(file_path);
    let dir = path.parent().unwrap();

    if !dir.exists() {
        fs::create_dir_all(&dir).expect("\nFailed to Create Directory\n");
    }

    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
        .expect("\nFailed to Create File\n");

    file.write((&content).as_ref()).expect("\nFailed to Write to File\n");
}

/// Reads the content of a file at the given file path as a string.
/// Returns the file content.
fn read_string_from_file(file_path: &str) -> String {
    fs::read_to_string(file_path).expect("\nFailed to Read from File\n")
}

pub(crate) fn save_vault(vault: &Vault) {
    let vault_name = vault.get_vault_name();
    let vault_string = encrypt_vault(&vault);
    let vault_path = format!("{}/{}.vault", VAULT_DIRECTORY, vault_name);

    save_string_to_file(&vault_path, &vault_string);
}

pub(crate) fn load_vault(vault_name: &str, vault_password: &str) -> Vault {
    let vault_path = format!("{}/{}.vault", VAULT_DIRECTORY, vault_name);
    let vault_string = read_string_from_file(&vault_path);
    decrypt_vault(&vault_string, vault_password)
}

pub(crate) fn clear_screen() {
    clear().expect("\nFailed to Clear Screen\n");
}

pub(crate) fn get_input(prompt: &str) -> String {
    print!("{}", prompt);
    stdout().flush().expect("\nFailed to Flush Stdout\n");
    let mut input = String::new();
    stdin().read_line(&mut input).expect("\nFailed to Read Input\n");
    input.trim().to_string()
}