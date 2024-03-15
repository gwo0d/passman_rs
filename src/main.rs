use argon2;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use chrono;
use rand;
use std::fs::File;
use std::io::Write;
use serde::{Deserialize, Serialize};

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
    key: String,
    creation_date: String,
}

impl Vault {
    pub fn new(name: String, password: String) -> Vault {
        let salt = SaltString::generate(&mut rand::rngs::OsRng).to_string();
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

fn hash_password(password: String, salt: String) -> String {
    let argon2 = Argon2::default();
    argon2.hash_password(password.as_ref(), SaltString::from_b64(salt.as_ref()).unwrap().as_salt()).unwrap().to_string()
}

fn save_vault(vault: Vault) {
    let filename = format!("{}.vault", vault.name);
    let file = File::create(filename);
    let json = serde_json::to_string(&vault).unwrap().to_string();
    file.unwrap().write_all(json.as_bytes()).expect("COULD NOT WRITE TO VAULT");
    println!("{:?}", json);
}

fn main() {
    let mut vault = Vault::new("testvault".parse().unwrap(), "password".to_string());
    let cred1 = Credential::new("facebook".parse().unwrap(), "facebook.com".parse().unwrap(), "mark".parse().unwrap(), "thezuck".parse().unwrap(), String::new());
    vault.add_credential(cred1);
    save_vault(vault);
}
