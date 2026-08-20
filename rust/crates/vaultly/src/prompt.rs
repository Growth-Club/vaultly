//! Interactive prompts — mirrors src/prompt.ts behaviors for the CLI.

use std::io::{self, Write};

pub fn prompt_line(prompt: &str) -> String {
    print!("{}", prompt);
    let _ = io::stdout().flush();
    let mut line = String::new();
    if io::stdin().read_line(&mut line).is_err() {
        return String::new();
    }
    line.trim().to_string()
}

pub fn prompt_password(prompt: &str) -> String {
    print!("{}", prompt);
    let _ = io::stdout().flush();
    rpassword::read_password().unwrap_or_default()
}

pub fn prompt_confirm(prompt: &str) -> bool {
    let answer = prompt_line(&format!("{} [y/N] ", prompt));
    matches!(answer.as_str(), "y" | "Y" | "yes" | "Yes" | "YES")
}
