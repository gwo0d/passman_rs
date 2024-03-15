use time;

struct Credential {
    service_name: String,
    service_url: Option<String>,
    username: String,
    password: String,
    notes: String,
    date_added: time::Date,
}

impl Credential {
    fn new(service_name: String, service_url: String, username: String, password: String, notes: String, date_added: time::Date) -> Credential {
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

fn main() {
    println!("Hello, world!");
}