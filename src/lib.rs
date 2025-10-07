//! The `nilauth` service manages blind module subscriptions and mints root Nucs
//! that grant access to them. It provides a RESTful API for clients to
//! manage payments, check subscription status, and request tokens.

/// Command-line arguments.
pub mod args;
/// Service configuration structure and loading logic.
pub mod config;
/// The main application entry point and server setup logic.
pub mod run;

mod auth;
mod cleanup;
mod db;
mod docs;
mod metrics;
mod routes;
mod services;
mod signed;
mod state;
mod time;

#[cfg(test)]
pub(crate) mod tests;
