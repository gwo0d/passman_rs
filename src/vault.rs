use crate::credential::Credential;
use crate::utils::{derive_key, generate_salt, generate_random_id};
use crate::constants::{KEY_SIZE, SALT_SIZE};

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

    pub fn get_salt(&self) -> [u8; 32] {
        self.salt
    }

    pub fn get_vault_key(&self) -> [u8; 32] {
        self.vault_key
    }

    pub fn set_vault_name(&mut self, vault_name: String) {
        self.vault_name = vault_name;
    }

    pub fn change_password(&mut self, password: &[u8]) -> None {
        self.vault_key = derive_key(password, &self.salt)
    }

    pub fn add_credential(&mut self, username: String, password: String, service: String, notes: Option<String>) -> None {
        let mut id: u64 = generate_random_id();
        let mut available: bool = true;

        loop {
            for credential in self.credentials {
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

        self.credentials.push(Credential::new(id, username, password, service, notes))
    }
}