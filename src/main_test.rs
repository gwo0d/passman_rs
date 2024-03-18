use crate::{decrypt_vault, encrypt_vault, hash_password, Credential, Vault};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_creation() {
        let credential = Credential::new(
            "Test Service".to_string(),
            "https://test.com".to_string(),
            "testuser".to_string(),
            "testpassword".to_string(),
            "Test notes".to_string(),
        );

        assert_eq!(credential.service_name, "Test Service");
        assert_eq!(credential.service_url.unwrap(), "https://test.com");
        assert_eq!(credential.username, "testuser");
        assert_eq!(credential.password, "testpassword");
        assert_eq!(credential.notes.unwrap(), "Test notes");
    }

    #[test]
    fn vault_creation_and_password_change() {
        let mut vault = Vault::new("Test Vault".to_string(), "testpassword".to_string());

        assert_eq!(vault.name, "Test Vault");
        assert_eq!(vault.credentials.len(), 0);

        vault.change_vault_password("newpassword".to_string());
        let new_key = hash_password("newpassword".to_string(), vault.salt.clone());

        assert_eq!(vault.key, new_key);
    }

    #[test]
    fn vault_add_and_remove_credential() {
        let mut vault = Vault::new("Test Vault".to_string(), "testpassword".to_string());
        let credential = Credential::new(
            "Test Service".to_string(),
            "https://test.com".to_string(),
            "testuser".to_string(),
            "testpassword".to_string(),
            "Test notes".to_string(),
        );

        vault.add_credential(credential.clone());
        assert_eq!(vault.credentials.len(), 1);

        vault.remove_credential("Test Service".to_string());
        assert_eq!(vault.credentials.len(), 0);
    }

    #[test]
    fn vault_file_encryption_and_decryption() {
        let vault = Vault::new("Test Vault".to_string(), "testpassword".to_string());
        let vault_file = encrypt_vault(&vault);
        let decrypted_vault = decrypt_vault(vault_file, "testpassword".to_string());

        assert_eq!(vault.name, decrypted_vault.name);
        assert_eq!(vault.salt, decrypted_vault.salt);
        assert_eq!(vault.key, decrypted_vault.key);
        assert_eq!(vault.credentials.len(), decrypted_vault.credentials.len());
    }
}
