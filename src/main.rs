use argon2;
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;
use rand;
use chrono;
use chrono::{DateTime, Utc};

struct Credential {
    service_name: String,
    service_url: Option<String>,
    username: String,
    password: String,
    notes: String,
    date_added: DateTime<Utc>,
}

impl Credential {
    fn new(service_name: String, service_url: String, username: String, password: String, notes: String, date_added: DateTime<Utc>) -> Credential {
        Credential {
            service_name,
            service_url: Some(service_url),
            username,
            password,
            notes,
            date_added,
        }
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
            salt: salt,
            key: argon2.hash_password(password.as_ref(), &salt)?.to_string(),
            creation_date: chrono::offset::Utc::now()
        }
    }
}

fn main() {
    println!("Hello, world!");
}