use serde::{Deserialize, Serialize};

use crate::constants::{KEY_BYTES, SALT_BYTES};
use crate::credential::Credential;
use crate::utils::{derive_key, generate_random_id, generate_salt};

/// The `Vault` struct represents a secure container for storing credentials.
/// It includes a vault name, a salt for password hashing, a vault key, and a list of credentials.
#[derive(Serialize, Deserialize)]
pub(crate) struct Vault {
    vault_name: String,
    salt: [u8; SALT_BYTES],
    vault_key: [u8; KEY_BYTES],
    credentials: Vec<Credential>,
}

impl Vault {
    /// Creates a new `Vault` with the given name and password.
    pub fn new(vault_name: &str, password: &str) -> Self {
        let salt = generate_salt();

        Self {
            vault_name: vault_name.to_string(),
            salt,
            vault_key: derive_key(password.as_bytes(), &salt),
            credentials: Vec::new(),
        }
    }

    /// Returns the name of the vault.
    pub fn get_vault_name(&self) -> &str {
        &self.vault_name
    }

    /// Returns the salt used for password hashing.
    pub fn get_salt(&self) -> &[u8; 32] {
        &self.salt
    }

    /// Returns the vault key.
    pub fn get_vault_key(&self) -> &[u8; 32] {
        &self.vault_key
    }

    /// Sets the name of the vault.
    pub fn set_vault_name(&mut self, vault_name: String) {
        self.vault_name = vault_name;
    }

    /// Sets the vault password by deriving a new key from the given password and the existing salt.
    pub fn set_vault_password(&mut self, password: &[u8]) {
        self.vault_key = derive_key(password, &self.salt);
    }

    /// Adds a new credential to the vault.
    /// Generates a unique ID for the credential and ensures it does not conflict with existing IDs.
    pub fn add_credential(&mut self, username: String, password: String, service: String, notes: String) {
        let mut id: u64 = generate_random_id();
        let mut available: bool = true;

        loop {
            for credential in self.credentials.iter() {
                if credential.get_id() == &id {
                    available = false;
                    break;
                }
            }

            if available {
                break;
            } else {
                id = generate_random_id()
            }
        }

        self.credentials.push(Credential::new(id, username, password, service, notes));
    }

    /// Searches for credentials by service name.
    /// Returns a vector of references to the matching credentials.
    pub fn search_credential_by_str(&self, search_string: String) -> Vec<&Credential> {
        self.credentials.iter().filter(|cred| cred.get_service().contains(&search_string) || cred.get_notes().contains(&search_string)).collect()
    }

    /// Deletes a credential by its ID.
    /// Returns true if the credential was found and deleted, false otherwise.
    pub fn delete_credential_by_id(&mut self, id: u64) -> bool {
        match self.credentials.iter().position(|cred| cred.get_id() == &id) {
            Some(index) => {
                self.credentials.remove(index);
                true
            },
            None => false,
        }
    }
}