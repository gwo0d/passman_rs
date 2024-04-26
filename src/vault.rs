use serde::{Deserialize, Serialize};

use crate::constants::{KEY_SIZE, SALT_SIZE};
use crate::credential::Credential;
use crate::utils::{derive_key, generate_random_id, generate_salt};

#[derive(Serialize, Deserialize)]
pub struct Vault {
    vault_name: String,
    salt: [u8; SALT_SIZE],
    vault_key: [u8; KEY_SIZE],
    credentials: Vec<Credential>,
}

impl Vault {
    pub fn new(vault_name: String, password: &[u8]) -> Self {
        let salt = generate_salt();

        Self {
            vault_name,
            salt,
            vault_key: derive_key(password, &salt),
            credentials: Vec::new(),
        }
    }

    pub fn get_vault_name(&self) -> &str {
        &self.vault_name
    }

    pub fn get_salt(&self) -> &[u8; 32] {
        &self.salt
    }

    pub fn get_vault_key(&self) -> &[u8; 32] {
        &self.vault_key
    }

    pub fn set_vault_name(&mut self, vault_name: String) {
        self.vault_name = vault_name;
    }

    pub fn set_vault_password(&mut self, password: &[u8]) {
        self.vault_key = derive_key(password, &self.salt);
    }

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

    pub fn search_credential_by_str(&self, search_string: String) -> Vec<&Credential> {
        self.credentials.iter().filter(|cred| cred.get_service().contains(&search_string)).collect()
    }

    pub fn delete_credential_by_id(&mut self, id: u64) -> bool {
        let index = self.credentials.iter().position(|cred| cred.get_id() == &id).expect("\nCredential Not Found\n");
        if Some(index).is_some() {
            self.credentials.remove(index);
            true
        } else {
            false
        }
    }
}