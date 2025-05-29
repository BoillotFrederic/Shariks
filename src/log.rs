//! # Log Module - Shariks Chain
//!
//! The "Log" module provides helper functions and shared utilities used throughout the code to
//! make writing logs easier.

// Dependencies
use std::fmt::Display;

// Log
// ---

pub struct Log;

#[allow(unused)]
impl Log {
    // Errors
    pub fn error<E: std::fmt::Display>(module: &str, function: &str, message: &str, e: E) {
        eprintln!("[ERROR] {}::{} -> {} : {}", module, function, message, e);
    }
    pub fn error_msg(module: &str, function: &str, message: &str) {
        eprintln!("[ERROR] {}::{} -> {}", module, function, message);
    }

    // Warnings
    pub fn warn<E: Display>(module: &str, function: &str, message: &str, e: E) {
        eprintln!("[WARN]  {}::{} -> {} : {}", module, function, message, e);
    }
    pub fn warn_msg(module: &str, function: &str, message: &str) {
        eprintln!("[WARN] {}::{} -> {}", module, function, message);
    }

    // Infos
    pub fn info<E: Display>(module: &str, function: &str, message: &str, e: E) {
        println!("[INFO]  {}::{} -> {} : {}", module, function, message, e);
    }
    pub fn info_msg(module: &str, function: &str, message: &str) {
        println!("[INFO]  {}::{} -> {}", module, function, message);
    }

    // Debugs
    pub fn debug<E: Display>(module: &str, function: &str, message: &str, e: E) {
        println!("[DEBUG] {}::{} -> {} : {}", module, function, message, e);
    }
    pub fn debug_msg(module: &str, function: &str, message: &str) {
        eprintln!("[DEBUG] {}::{} -> {}", module, function, message);
    }
}
