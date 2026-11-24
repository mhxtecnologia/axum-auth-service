//! Testes de integração: HTTP de verdade contra Postgres e Redis de verdade.
//! Pré-requisito local: `docker compose up -d postgres redis`.

mod health;
mod helpers;
mod jwks;
mod login;
mod observability;
mod rate_limit;
mod refresh;
mod register;
