use std::io;

pub(crate) struct Cli {
    menu_options: Vec<String>,
}

impl Cli {
    pub fn new(menu_options: Vec<String>) -> Self {
        Self {
            menu_options,
        }
    }

    pub fn show_menu(&self) {
        for (index, option) in self.menu_options.iter().enumerate() {
            println!("{}. {}", index + 1, option);
        }
    }

    pub fn get_input(&self) -> u8 {
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("\nFailed to Read Line\n");

        input.trim().parse().expect("\nInvalid Input\n")
    }
}