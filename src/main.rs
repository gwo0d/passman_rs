use std::fs::File;
use std::io::{Read, Write};
use std::str::FromStr;

use aes_gcm_siv;
use aes_gcm_siv::aead::Aead;
use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce};
use argon2;
use argon2::Argon2;
use chrono;
use rand;
use rand::rngs::OsRng;
use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Credential {
    service_name: String,
    service_url: Option<String>,
    username: String,
    password: String,
    notes: Option<String>,
    date_added: String,
}

impl Credential {
    fn new(
        service_name: String,
        service_url: String,
        username: String,
        password: String,
        notes: String,
    ) -> Credential {
        Credential {
            service_name,
            service_url: Some(service_url),
            username,
            password,
            notes: Some(notes),
            date_added: chrono::offset::Utc::now().to_string(),
        }
    }

    pub fn set_service_name(&mut self, service_name: String) {
        self.service_name = service_name;
    }

    pub fn set_service_url(&mut self, service_url: String) {
        self.service_url = Some(service_url);
    }

    pub fn set_username(&mut self, username: String) {
        self.username = username;
    }

    pub fn set_password(&mut self, password: String) {
        self.password = password;
    }

    pub fn set_notes(&mut self, notes: String) {
        self.notes = Some(notes);
    }
}

#[derive(Serialize, Deserialize)]
struct Vault {
    name: String,
    credentials: Vec<Credential>,
    salt: Vec<u8>,
    key: [u8; 32],
    creation_date: String,
}

impl Vault {
    pub fn new(name: String, password: String) -> Vault {
        let salt: Vec<u8> = OsRng.gen::<[u8; 32]>().to_vec();

        Vault {
            name,
            credentials: Vec::new(),
            salt: salt.clone(),
            key: hash_password(password, salt.clone()),
            creation_date: chrono::offset::Utc::now().to_string(),
        }
    }

    pub fn add_credential(&mut self, credential: Credential) {
        self.credentials.push(credential);
    }

    pub fn remove_credential(&mut self, service_name: String) {
        self.credentials.retain(|x| x.service_name != service_name);
    }

    pub fn change_vault_password(&mut self, new_password: String) {
        self.key = hash_password(new_password, self.salt.clone())
    }
}

#[derive(Serialize, Deserialize)]
struct VaultFile {
    salt: Vec<u8>,
    nonce: [u8; 12],
    name: String,
    encrypted_vault: Vec<u8>,
}

impl VaultFile {
    pub fn new(
        salt: Vec<u8>,
        nonce: [u8; 12],
        name: String,
        encrypted_vault: Vec<u8>,
    ) -> VaultFile {
        VaultFile {
            salt,
            nonce,
            name,
            encrypted_vault,
        }
    }
}

fn hash_password(password: String, salt: Vec<u8>) -> [u8; 32] {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_ref(), &*salt, &mut key)
        .expect("COULD NOT HASH PASSWORD");
    key
}

fn save_vault(vault_file: VaultFile) {
    let mut file = File::create(format!("{}.vault", vault_file.name)).unwrap();
    file.write_all(&serde_json::to_string(&vault_file).unwrap().as_bytes())
        .expect("COULD NOT SAVE VAULT");
}

fn encrypt_vault(vault: &Vault) -> VaultFile {
    let plaintext = serde_json::to_string(&vault).unwrap();
    let salt = vault.salt.clone();
    let nonce = OsRng.gen::<[u8; 12]>();

    let cipher = Aes256GcmSiv::new_from_slice(vault.key.as_ref()).unwrap();
    let mut ciphertext = cipher.encrypt(&Nonce::from_slice(&nonce), plaintext.as_bytes().as_ref());

    VaultFile::new(salt, nonce, vault.name.clone(), ciphertext.unwrap())
}

fn load_vault(vault_name: String) -> VaultFile {
    let mut file = File::open(format!("{}.vault", vault_name)).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let vault_file: VaultFile = serde_json::from_str(&contents).unwrap();
    vault_file
}

fn decrypt_vault(vault_file: VaultFile, password: String) -> Vault {
    let nonce = Nonce::from_slice(vault_file.nonce.as_ref());
    let key = hash_password(password, vault_file.salt.clone());
    let cipher = Aes256GcmSiv::new_from_slice(key.as_ref()).unwrap();
    let plaintext = cipher.decrypt(nonce, vault_file.encrypted_vault.as_ref());

    serde_json::from_str(&String::from_utf8(plaintext.unwrap()).unwrap()).unwrap()
}

fn main() {
    let mut vault = Vault::new("testvault".parse().unwrap(), "password".to_string());
    let cred1 = Credential::new(
        "facebook".parse().unwrap(),
        "facebook.com".parse().unwrap(),
        "mark".parse().unwrap(),
        "thezuck".parse().unwrap(),
        String::new(),
    );

    vault.add_credential(cred1);
    let encrypted_vault = encrypt_vault(&vault);

    save_vault(encrypted_vault);
    let vault_file = load_vault(String::from_str("testvault").unwrap());
    let decrypted_vault = decrypt_vault(vault_file, "password".to_string());
    println!("{}", decrypted_vault.credentials[0].service_name);
}
