pub struct Credential {
    username: String,
    password: String,
    service: String,
    notes: Option<String>,
}

impl Credential {
    pub fn new(username: String, password: String, service: String, notes: Option<String>) -> Self {
        Self { username, password, service, notes }
    }

    pub fn get_username(&self) -> &str {
        &self.username
    }
    pub fn get_password(&self) -> &str {
        &self.password
    }
    pub fn get_service(&self) -> &str {
        &self.service
    }
    pub fn get_notes(&self) -> &Option<String> {
        &self.notes
    }
    pub fn set_password(&mut self, password: String) {
        self.password = password;
    }
    pub fn set_notes(&mut self, notes: Option<String>) {
        self.notes = notes;
    }
}