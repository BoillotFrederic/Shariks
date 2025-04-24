// Dependencies
use std::time::{SystemTime, UNIX_EPOCH};
use std::io;

// Current date
pub fn current_timestamp() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()
}

// Simple prompt
pub fn prompt(text: &str) -> String {
    println!("{}", text);
    let mut _prompt = String::new();
    io::stdin().read_line(&mut _prompt).expect("Error : read line");
    _prompt.trim().to_string()
}
