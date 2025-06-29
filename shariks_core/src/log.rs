//! # Log Module - Shariks Chain
//!
//! The "Log" module provides helper functions and shared utilities used throughout the code to
//! make writing logs easier.

// Dependencies
use once_cell::sync::Lazy;
use std::fmt::Display;
use std::sync::atomic::{AtomicBool, Ordering};

// Global
pub static SILENT: Lazy<AtomicBool> = Lazy::new(|| AtomicBool::new(false));

// Log
// ---

pub struct Log;

#[allow(unused)]
impl Log {
    // Silent
    fn is_silent() -> bool {
        SILENT.load(Ordering::Relaxed)
    }

    pub fn set_silent(value: bool) {
        SILENT.store(value, Ordering::Relaxed);
    }

    // Errors
    pub fn error<E: std::fmt::Display>(module: &str, function: &str, message: &str, e: E) {
        if !Self::is_silent() {
            eprintln!("[ERROR] {}::{} -> {} : {}", module, function, message, e);
        }
    }
    pub fn error_msg(module: &str, function: &str, message: &str) {
        if !Self::is_silent() {
            eprintln!("[ERROR] {}::{} -> {}", module, function, message);
        }
    }

    // Warnings
    pub fn warn<E: Display>(module: &str, function: &str, message: &str, e: E) {
        if !Self::is_silent() {
            eprintln!("[WARN]  {}::{} -> {} : {}", module, function, message, e);
        }
    }
    pub fn warn_msg(module: &str, function: &str, message: &str) {
        if !Self::is_silent() {
            eprintln!("[WARN] {}::{} -> {}", module, function, message);
        }
    }

    // Infos
    pub fn info<E: Display>(module: &str, function: &str, message: &str, e: E) {
        if !Self::is_silent() {
            println!("[INFO]  {}::{} -> {} : {}", module, function, message, e);
        }
    }
    pub fn info_msg(module: &str, function: &str, message: &str) {
        if !Self::is_silent() {
            println!("[INFO]  {}::{} -> {}", module, function, message);
        }
    }

    // Debugs
    pub fn debug<E: Display>(module: &str, function: &str, message: &str, e: E) {
        if !Self::is_silent() {
            println!("[DEBUG] {}::{} -> {} : {}", module, function, message, e);
        }
    }
    pub fn debug_msg(module: &str, function: &str, message: &str) {
        if !Self::is_silent() {
            eprintln!("[DEBUG] {}::{} -> {}", module, function, message);
        }
    }
}
