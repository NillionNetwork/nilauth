//! The `nilauth` service manages blind module subscriptions and mints root Nucs
//! that grant access to them. It provides a RESTful API for clients to
//! manage payments, check subscription status, and request tokens.

pub mod args;
pub mod config;
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
