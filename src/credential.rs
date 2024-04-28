use serde::{Deserialize, Serialize};

/// The `Credential` struct represents a user's credentials for a specific service.
/// It includes an id, username, password, service, and notes.
#[derive(Serialize, Deserialize)]
pub struct Credential {
    id: u64,
    username: String,
    password: String,
    service: String,
    notes: String,
}

impl Credential {
    /// Creates a new `Credential` with the given id, username, password, service, and notes.
    pub fn new(id: u64, username: String, password: String, service: String, notes: String) -> Self {
        Self { id, username, password, service, notes }
    }

    /// Returns the id of the credential.
    pub fn get_id(&self) -> &u64 {
        &self.id
    }

    /// Returns the username of the credential.
    pub fn get_username(&self) -> &str {
        &self.username
    }

    /// Returns the password of the credential.
    pub fn get_password(&self) -> &str {
        &self.password
    }

    /// Returns the service of the credential.
    pub fn get_service(&self) -> &str {
        &self.service
    }

    /// Returns the notes of the credential.
    pub fn get_notes(&self) -> &str {
        &self.notes
    }

    /// Sets the password of the credential.
    pub fn set_password(&mut self, password: String) {
        self.password = password;
    }

    /// Sets the notes of the credential.
    pub fn set_notes(&mut self, notes: String) {
        self.notes = notes;
    }
}