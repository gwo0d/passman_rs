use std::io::*;

use crate::cli::Cli;
use crate::constants::INITIAL_MENU_ITEMS;
use crate::utils::*;
use crate::vault::Vault;

mod utils;
mod constants;
mod credential;
mod vault;
mod cli;

fn main() {
    let mut vault: Vault;

    loop {
        let initial_cli = Cli::new(INITIAL_MENU_ITEMS.to_vec());
        initial_cli.show_menu();
        let choice = initial_cli.get_input();

        match choice {
            1 => {
                let vault_name = get_input("Enter vault name: ");
                let vault_password = get_input("Enter vault password: ");

                vault = load_vault(&vault_name, &vault_password);

                println!("\nVault Loaded\n");
                break;
            }

            2 => {
                let vault_name = get_input("Enter vault name: ");
                let vault_password = get_input("Enter vault password: ");
                let confirm_password = get_input("Confirm vault password: ");

                if vault_password == confirm_password {
                    vault = Vault::new(&vault_name, &vault_password);
                    save_vault(&vault);

                    println!("\nVault Created, Saved, and Loaded\n");
                    break;
                } else {
                    println!("\nVault Not Created\n");
                }
            }

            3 => {
                return;
            }

            _ => {
                println!("\nInvalid Input\n");
            }
        }
    }
}