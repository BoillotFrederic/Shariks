// Dependencies
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

// Current date
pub fn current_timestamp() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
}

// Clean decimals
pub fn trim_trailing_zeros(value: f64) -> String {
    let s = format!("{:.10}", value);
    let trimmed = s.trim_end_matches('0').trim_end_matches('.');
    trimmed.to_string()
}

// Simple prompt
pub fn prompt(text: &str) -> String {
    println!("{}", text);
    let mut _prompt = String::new();
    io::stdin()
        .read_line(&mut _prompt)
        .expect("Error : read line");
    _prompt.trim().to_string()
}
