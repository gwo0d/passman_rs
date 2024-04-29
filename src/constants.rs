/// The `constants` module defines constant values used across the application.
/// It includes constants for key and salt sizes, as well as menu items.

/// The size of the key in bytes.
/// This constant is used in key derivation functions.
pub(crate) const KEY_BYTES: usize = 32;

/// The size of the salt in bytes.
/// This constant is used in salt generation functions.
pub(crate) const SALT_BYTES: usize = 32;

pub(crate) const VAULT_DIRECTORY: &str = "vaults";

/// The initial menu items displayed to the user.
/// This constant is used to populate the initial menu options.
pub(crate) const INITIAL_MENU_ITEMS: [&str; 3] = ["Load Vault", "Create New Vault", "Exit"];

/// The main menu items displayed to the user after a vault is loaded or created.
/// This constant is used to populate the main menu options.
pub(crate) const MAIN_MENU_ITEMS: [&str; 5] = ["Search Credentials", "Add New Credential", "Remove Credential", "Admin", "Exit"];