mod app;
mod help;
mod history_screen;
mod layout;
mod menu;
mod nix;
mod redact_screen;
mod results;
mod scan_runner;
mod settings;
mod theme;

pub use app::run;

#[cfg(test)]
mod nix_tests;
