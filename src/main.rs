use argon2;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use chrono;
use chrono::{DateTime, Utc};
use rand;

struct Credential {
    service_name: String,
    service_url: Option<String>,
    username: String,
    password: String,
    notes: String,
    date_added: DateTime<Utc>,
}

impl Credential {
    fn new(
        service_name: String,
        service_url: String,
        username: String,
        password: String,
        notes: String,
        date_added: DateTime<Utc>,
    ) -> Credential {
        Credential {
            service_name,
            service_url: Some(service_url),
            username,
            password,
            notes,
            date_added,
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

struct Vault {
    credentials: Vec<Credential>,
    salt: SaltString,
    key: String,
    creation_date: DateTime<Utc>,
}

impl Vault {
    pub fn new(password: String) -> Vault {
        let argon2 = Argon2::default();
        let salt = SaltString::generate(&mut rand::rngs::OsRng);
        Vault {
            credentials: Vec::new(),
            salt,
            key: argon2.hash_password(password.as_ref(), &salt)?.to_string(),
            creation_date: chrono::offset::Utc::now(),
        }
    }

    pub fn add_credential(
        &mut self,
        service_name: String,
        service_url: String,
        username: String,
        password: String,
        notes: String,
    ) {
        let credential = Credential::new(
            service_name,
            service_url,
            username,
            password,
            notes,
            chrono::offset::Utc::now(),
        );
        self.credentials.push(credential);
    }

    pub fn remove_credential(&mut self, service_name: String) {
        self.credentials.retain(|x| x.service_name != service_name);
    }

    pub fn change_vault_password(&mut self, new_password: String) {
        let argon2 = Argon2::default();
        self.key = argon2.hash_password(new_password.as_ref(), &self.salt)?.to_string();
    }
}

fn main() {
    println!("Hello, world!");
}
