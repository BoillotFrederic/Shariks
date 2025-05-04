// Dependencies
//use std::fs::File;
//use std::fs::OpenOptions;
use std::io::{self /*, Read, Write*/};
//use std::path::Path;
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

// // Increment a file
// pub fn increment_file<P: AsRef<Path>>(file_path: P) -> io::Result<u64> {
//     let mut file = OpenOptions::new()
//         .read(true)
//         .write(true)
//         .create(true)
//         .open(file_path)?;
//
//     let mut content = String::new();
//     file.read_to_string(&mut content)?;
//
//     let mut number = content.trim().parse::<u64>().unwrap_or(0);
//     number += 1;
//
//     file.set_len(0)?;
//     file.write_all(number.to_string().as_bytes())?;
//
//     Ok(number)
// }

// // Write file text
// pub fn write_to_file(filename: &str, content: &str) -> io::Result<()> {
//     let mut file = OpenOptions::new()
//         .create(true)
//         .append(true)
//         .open(filename)?;
//
//     writeln!(file, "{}", content)?;
//     Ok(())
// }
//
// // Read file text
// pub fn read_from_file(filename: &str) -> io::Result<String> {
//     let mut file = File::open(filename)?;
//     let mut content = String::new();
//
//     file.read_to_string(&mut content)?;
//     Ok(content)
// }
