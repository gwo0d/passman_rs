use argon2;
use argon2::password_hash::SaltString;
use argon2::{Argon2};
use chrono;
use rand;
use std::fs::File;
use std::io::{Read, Write};
use serde::{Deserialize, Serialize};
use aes_gcm_siv;
use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce};
use aes_gcm_siv::aead::Aead;
use aes_gcm_siv::aead::rand_core::RngCore;
use rand::rngs::OsRng;


#[derive(Serialize, Deserialize)]
struct Credential {
    service_name: String,
    service_url: Option<String>,
    username: String,
    password: String,
    notes: String,
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
            notes,
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
        self.notes = notes;
    }
}

#[derive(Serialize, Deserialize)]
struct Vault {
    name: String,
    credentials: Vec<Credential>,
    salt: String,
    key: [u8; 32],
    creation_date: String,
}

impl Vault {
    pub fn new(name: String, password: String) -> Vault {
        let salt = SaltString::generate(&mut OsRng).to_string();
        Vault {
            name,
            credentials: Vec::new(),
            salt: salt.clone(),
            key: hash_password(password, salt.clone()),
            creation_date: chrono::offset::Utc::now().to_string(),
        }
    }

    pub fn add_credential(
        &mut self,
        credential: Credential,
    ) {
        self.credentials.push(credential);
    }

    pub fn remove_credential(&mut self, service_name: String) {
        self.credentials.retain(|x| x.service_name != service_name);
    }

    pub fn change_vault_password(&mut self, new_password: String) {
        self.key = hash_password(new_password, self.salt.clone())
    }
}

fn hash_password(password: String, salt: String) -> [u8; 32] {
    let mut key = [0u8; 32];
    Argon2::default().hash_password_into(password.as_ref(), salt.as_ref(), &mut key).expect("COULD NOT HASH PASSWORD");
    key
}

fn encrypt_vault(vault: Vault, plaintext: String, nonce: Nonce) -> Vec<u8> {
    let cipher = Aes256GcmSiv::new_from_slice(vault.key.as_ref()).unwrap();
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes().as_ref());
    return ciphertext.unwrap();
}

fn save_vault(vault: Vault) {
    let filename = format!("{}.vault", vault.name);
    let file = File::create(filename);
    let json = serde_json::to_string(&vault).unwrap().to_string();
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);
    let mut ciphertext = nonce.to_vec();
    ciphertext.append(&mut encrypt_vault(vault, json.clone(), nonce));
    file.unwrap().write_all(&*ciphertext).expect("COULD NOT WRITE TO VAULT");
    println!("{:?}", json);
}

fn load_vault(name: String, password: String) -> Vault {
    let filename = format!("{}.vault", name);
    let file = File::open(filename);
    let mut contents = String::new();
    file.unwrap().read_to_string(&mut contents).expect("COULD NOT READ VAULT");
    let vault: Vault = serde_json::from_str(&contents).unwrap();
    if vault.key == hash_password(password, vault.salt.clone()) {
        return vault;
    } else {
        panic!("INCORRECT PASSWORD");
    }
}

fn main() {
    let mut vault = Vault::new("testvault".parse().unwrap(), "password".to_string());
    let cred1 = Credential::new("facebook".parse().unwrap(), "facebook.com".parse().unwrap(), "mark".parse().unwrap(), "thezuck".parse().unwrap(), String::new());
    vault.add_credential(cred1);
    save_vault(vault);
    //let vault = load_vault("testvault".parse().unwrap(), "password".to_string());
    //println!("{}", vault.credentials[0].password);
}
