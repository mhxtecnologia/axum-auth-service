//! Serviço de autenticação: cadastro, login, refresh com rotação e logout.

pub mod auth;
pub mod configuration;
pub mod crypto;
pub mod domain;
pub mod error;
pub mod extract;
pub mod openapi;
pub mod rate_limit;
pub mod repository;
pub mod routes;
pub mod startup;
pub mod telemetry;
