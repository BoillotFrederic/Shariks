//! # Utils Module - Shariks Chain
//!
//! The `utils` module provides helper functions and shared utilities used across
//! the Shariks blockchain codebase. These functions are lightweight, reusable,
//! and aim to reduce duplication in core logic.

// Dependencies
use futures::StreamExt;
use rpassword::read_password;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time;

// Utils
// -----

pub struct Utils;

impl Utils {
    /// Cleaning up trailing zeros
    pub fn trim_trailing_zeros(value: f64) -> String {
        let s = format!("{:.10}", value);
        let trimmed = s.trim_end_matches('0').trim_end_matches('.');
        trimmed.to_string()
    }

    /// Simple prompt
    pub fn prompt(text: &str) -> String {
        println!("{}", text);
        let mut _prompt = String::new();
        io::stdin()
            .read_line(&mut _prompt)
            .expect("Error : read line");
        _prompt.trim().to_string()
    }

    /// Secret prompt
    pub fn prompt_secret(text: &str) -> String {
        println!("{}", text);
        read_password().unwrap_or_else(|_| "".to_string())
    }

    /// Current date in timestamp
    pub fn current_timestamp() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
    }

    /// SQLX query with a timeout
    pub async fn with_timeout<T, F>(fut: F, secs: u64) -> Result<T, sqlx::Error>
    where
        F: std::future::Future<Output = Result<T, sqlx::Error>> + Send,
    {
        time::timeout(Duration::from_secs(secs), fut)
            .await
            .map_err(|_| sqlx::Error::Protocol("Timeout".into()))?
    }

    /// SQLX query streamed with a timeout
    pub async fn with_timeout_next<'a, S>(
        stream: &'a mut S,
        secs: u64,
    ) -> Result<Option<S::Item>, &'static str>
    where
        S: futures::Stream + Unpin,
    {
        tokio::time::timeout(Duration::from_secs(secs), stream.next())
            .await
            .map_err(|_| "Timeout")
    }

    /// Increment a file
    #[allow(unused)]
    pub fn increment_file<P: AsRef<Path>>(file_path: P) -> io::Result<u64> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(file_path)?;

        let mut content = String::new();
        file.read_to_string(&mut content)?;

        let mut number = content.trim().parse::<u64>().unwrap_or(0);
        number += 1;

        file.set_len(0)?;
        file.write_all(number.to_string().as_bytes())?;

        Ok(number)
    }

    /// Write file with a text
    pub fn write_to_file(filename: &str, content: &str) -> io::Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(filename)?;

        writeln!(file, "{}", content)?;
        Ok(())
    }

    /// Read all text in file
    pub fn read_from_file(filename: &str) -> io::Result<String> {
        let mut file = File::open(filename)?;
        let mut content = String::new();

        file.read_to_string(&mut content)?;
        Ok(content)
    }
}
