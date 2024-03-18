// Import necessary libraries
use std::fs::File;
use std::io::{Read, Write};
use std::str::FromStr;

use aes_gcm_siv;
use aes_gcm_siv::aead::Aead;
use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce};
use argon2;
use argon2::Argon2;
use chrono;
use clearscreen;
use cli_table::{print_stdout, Cell, Style, Table};
use rand;
use rand::rngs::OsRng;
use rand::Rng;
use serde::{Deserialize, Serialize};

const FIRST_MENU_ITEMS: [&str; 3] = ["Create New Vault", "Load Existing Vault", "Exit"];

const MAIN_MENU_ITEMS: [&str; 6] = [
    "Get Credentials",
    "Add Credential",
    "Remove Credential",
    "Change Vault Password",
    "Save Vault",
    "Exit",
];

// Define the Credential struct
#[derive(Serialize, Deserialize, Clone)]
struct Credential {
    service_name: String,
    service_url: Option<String>,
    username: String,
    password: String,
    notes: Option<String>,
    date_added: String,
}

// Implement methods for the Credential struct
impl Credential {
    // Constructor for the Credential struct
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

    // Setter methods for the Credential struct
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

// Define the Vault struct
#[derive(Serialize, Deserialize, Clone)]
struct Vault {
    name: String,
    credentials: Vec<Credential>,
    salt: Vec<u8>,
    key: [u8; 32],
    creation_date: String,
}

// Implement methods for the Vault struct
impl Vault {
    // Constructor for the Vault struct
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

    // Method to add a credential to the vault
    pub fn add_credential(&mut self, credential: Credential) {
        self.credentials.push(credential);
    }

    // Method to remove a credential from the vault
    pub fn remove_credential(&mut self, service_name: String) {
        self.credentials.retain(|x| x.service_name != service_name);
    }

    // Method to change the vault password
    pub fn change_vault_password(&mut self, new_password: String) {
        self.key = hash_password(new_password, self.salt.clone())
    }

    pub fn get_vec_credentials(&self) -> Vec<Credential> {
        self.credentials.clone()
    }
}

// Define the VaultFile struct
#[derive(Serialize, Deserialize)]
struct VaultFile {
    salt: Vec<u8>,
    nonce: [u8; 12],
    name: String,
    encrypted_vault: Vec<u8>,
}

// Implement methods for the VaultFile struct
impl VaultFile {
    // Constructor for the VaultFile struct
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

struct Menu {
    options: Vec<String>,
}

impl Menu {
    pub fn new(options: Vec<String>) -> Menu {
        Menu { options }
    }

    pub fn display(&self) {
        for (i, option) in self.options.iter().enumerate() {
            println!("{}. {}", i + 1, option);
        }
    }

    pub fn get_choice(&self) -> usize {
        let mut choice = String::new();
        println!("Enter your choice: ");
        std::io::stdin()
            .read_line(&mut choice)
            .expect("COULD NOT READ LINE");
        let choice = choice.trim().parse::<usize>().unwrap();
        clear_screen();
        choice
    }
}

struct Cli {
    window_x: u8,
    window_y: u8,
    vault: Vault,
}

impl Cli {
    pub fn new(window_x: u8, window_y: u8, vault: Vault) -> Cli {
        Cli {
            window_x,
            window_y,
            vault,
        }
    }

    pub fn display(&self, revealed: Option<Vec<usize>>) {
        let mut output = vec![];
        let mut index = 1;

        let mut revealed = if revealed.is_none() {
            Vec::new()
        } else {
            revealed.unwrap()
        };

        for credential in self.vault.get_vec_credentials() {
            output.push(vec![
                index.to_string().cell(),
                credential.service_name.cell(),
                credential.service_url.unwrap().cell(),
                credential.username.cell(),
                if revealed.contains(&index) {
                    credential.password.cell()
                } else {
                    "********".cell()
                },
                credential.notes.unwrap().cell(),
                credential.date_added.cell(),
            ]);
            index += 1;
        }

        let table = output.table().title(vec![
            "Index".cell().bold(true),
            "Service Name".cell().bold(true),
            "Service URL".cell().bold(true),
            "Username".cell().bold(true),
            "Password".cell().bold(true),
            "Notes".cell().bold(true),
            "Date Added".cell().bold(true),
        ]);

        print_stdout(table).unwrap();
    }
}

// Function to hash the password
fn hash_password(password: String, salt: Vec<u8>) -> [u8; 32] {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_ref(), &*salt, &mut key)
        .expect("COULD NOT HASH PASSWORD");
    key
}

// Function to save the vault to a file
fn save_vault(vault_file: VaultFile) {
    let mut file = File::create(format!("{}.vault", vault_file.name)).unwrap();
    file.write_all(&serde_json::to_string(&vault_file).unwrap().as_bytes())
        .expect("COULD NOT SAVE VAULT");
}

// Function to encrypt the vault
fn encrypt_vault(vault: &Vault) -> VaultFile {
    let plaintext = serde_json::to_string(&vault).unwrap();
    let salt = vault.salt.clone();
    let nonce = OsRng.gen::<[u8; 12]>();

    let cipher = Aes256GcmSiv::new_from_slice(vault.key.as_ref()).unwrap();
    let mut ciphertext = cipher.encrypt(&Nonce::from_slice(&nonce), plaintext.as_bytes().as_ref());

    VaultFile::new(salt, nonce, vault.name.clone(), ciphertext.unwrap())
}

// Function to load the vault from a file
fn load_vault(vault_name: String) -> VaultFile {
    let mut file = File::open(format!("{}.vault", vault_name)).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let vault_file: VaultFile = serde_json::from_str(&contents).unwrap();
    vault_file
}

// Function to decrypt the vault
fn decrypt_vault(vault_file: VaultFile, password: String) -> Vault {
    let nonce = Nonce::from_slice(vault_file.nonce.as_ref());
    let key = hash_password(password, vault_file.salt.clone());
    let cipher = Aes256GcmSiv::new_from_slice(key.as_ref()).unwrap();
    let plaintext = cipher.decrypt(nonce, vault_file.encrypted_vault.as_ref());

    serde_json::from_str(&String::from_utf8(plaintext.unwrap()).unwrap()).unwrap()
}

fn clear_screen() {
    clearscreen::clear().expect("FAILED TO CLEAR SCREEN");
}

// Main function
fn main() {
    clear_screen();

    let initial_menu = Menu::new(FIRST_MENU_ITEMS.iter().map(|x| x.to_string()).collect());
    let main_menu = Menu::new(MAIN_MENU_ITEMS.iter().map(|x| x.to_string()).collect());

    initial_menu.display();
    let choice = initial_menu.get_choice();

    let mut vault: Vault;

    match choice {
        1 => {
            clear_screen();
            println!("Enter the name of the vault: ");
            let mut vault_name = String::new();
            std::io::stdin()
                .read_line(&mut vault_name)
                .expect("COULD NOT READ LINE");
            let vault_name = vault_name.trim().to_string();

            println!("Enter the password for the vault: ");
            let mut password = String::new();
            std::io::stdin()
                .read_line(&mut password)
                .expect("COULD NOT READ LINE");
            let password = password.trim().to_string();

            vault = Vault::new(vault_name.clone(), password.clone());
            let vault_file = encrypt_vault(&vault);
            save_vault(vault_file);
            clear_screen();
        }

        2 => {
            clear_screen();
            println!("Enter the name of the vault: ");
            let mut vault_name = String::new();
            std::io::stdin()
                .read_line(&mut vault_name)
                .expect("COULD NOT READ LINE");
            let vault_name = vault_name.trim().to_string();

            println!("Enter the password for the vault: ");
            let mut password = String::new();
            std::io::stdin()
                .read_line(&mut password)
                .expect("COULD NOT READ LINE");
            let password = password.trim().to_string();

            let vault_file = load_vault(vault_name.clone());
            vault = decrypt_vault(vault_file, password.clone());
            clear_screen();
        }

        3 => {
            clear_screen();
            return;
        }

        _ => {
            clear_screen();
            println!("Invalid choice");
            return;
        }
    }

    loop {
        main_menu.display();
        let choice = main_menu.get_choice();

        match choice {
            1 => {
                clear_screen();
                let cli = Cli::new(80, 24, vault.clone());
                cli.display(None);
                println!("Enter the index(s) of the credential(s) you would like, seperated by a comma, to reveal the password(s): ");
                let mut indexes = String::new();
                std::io::stdin()
                    .read_line(&mut indexes)
                    .expect("COULD NOT READ LINE");

                let indexes: Vec<usize> = indexes
                    .split(",")
                    .map(|x| x.trim().parse::<usize>().expect("NO INDEXES PROVIDED") - 1)
                    .collect();

                clear_screen();

                cli.display(Some(indexes));
            }

            2 => {
                clear_screen();
                println!("Enter the service name: ");
                let mut service_name = String::new();
                std::io::stdin()
                    .read_line(&mut service_name)
                    .expect("COULD NOT READ LINE");
                let service_name = service_name.trim().to_string();

                println!("Enter the service URL: ");
                let mut service_url = String::new();
                std::io::stdin()
                    .read_line(&mut service_url)
                    .expect("COULD NOT READ LINE");
                let service_url = service_url.trim().to_string();

                println!("Enter the username: ");
                let mut username = String::new();
                std::io::stdin()
                    .read_line(&mut username)
                    .expect("COULD NOT READ LINE");
                let username = username.trim().to_string();

                println!("Enter the password: ");
                let mut password = String::new();
                std::io::stdin()
                    .read_line(&mut password)
                    .expect("COULD NOT READ LINE");
                let password = password.trim().to_string();

                println!("Enter any notes: ");
                let mut notes = String::new();
                std::io::stdin()
                    .read_line(&mut notes)
                    .expect("COULD NOT READ LINE");
                let notes = notes.trim().to_string();

                let credential =
                    Credential::new(service_name, service_url, username, password, notes);
                vault.add_credential(credential);
                clear_screen();
            }

            3 => {
                clear_screen();
                println!("Enter the service name: ");
                let mut service_name = String::new();
                std::io::stdin()
                    .read_line(&mut service_name)
                    .expect("COULD NOT READ LINE");
                let service_name = service_name.trim().to_string();

                vault.remove_credential(service_name);
                clear_screen();
            }

            4 => {
                clear_screen();
                println!("Enter the new password for the vault: ");
                let mut new_password = String::new();
                std::io::stdin()
                    .read_line(&mut new_password)
                    .expect("COULD NOT READ LINE");
                let new_password = new_password.trim().to_string();

                let mut current_password = String::new();
                println!("Enter the current password to confirm: ");
                std::io::stdin()
                    .read_line(&mut current_password)
                    .expect("COULD NOT READ LINE");
                let current_password = current_password.trim().to_string();
                let current_password_hash = hash_password(current_password, vault.salt.clone());

                if current_password_hash != vault.key {
                    println!("Invalid password");
                    continue;
                }

                vault.change_vault_password(new_password);
                clear_screen();
            }

            5 => {
                clear_screen();
                let vault_file = encrypt_vault(&vault);
                save_vault(vault_file);
                clear_screen();
            }

            6 => {
                clear_screen();
                return;
            }

            _ => {
                clear_screen();
                println!("Invalid choice");
                return;
            }
        }
    }
}
