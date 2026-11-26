// src/network/mod.rs
pub mod config;
pub mod routing;

pub use config::Config;
pub use routing::{InboundRouter, Route, RoutingError, RoutingStats};
