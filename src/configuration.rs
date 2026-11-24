//! Configuração em camadas: `base.yaml` → `<ambiente>.yaml` → variáveis `APP_*`.
//!
//! O ambiente vem de `APP_ENVIRONMENT` (`local` por padrão). Qualquer chave pode
//! ser sobrescrita por variável de ambiente com `__` separando os níveis, por
//! exemplo `APP_DATABASE__HOST=postgres`.

use std::path::PathBuf;

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use sqlx::postgres::{PgConnectOptions, PgSslMode};

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub application: ApplicationSettings,
    pub database: DatabaseSettings,
    pub redis: RedisSettings,
    pub jwt: JwtSettings,
    pub refresh_token: RefreshTokenSettings,
    pub password: PasswordSettings,
    pub rate_limit: RateLimitSettings,
    pub telemetry: TelemetrySettings,
}

#[derive(Debug, Deserialize)]
pub struct ApplicationSettings {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Deserialize)]
pub struct DatabaseSettings {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: SecretString,
    pub database_name: String,
    pub require_ssl: bool,
    pub max_connections: u32,
    pub run_migrations: bool,
}

impl DatabaseSettings {
    /// Opções de conexão sem banco escolhido (usado para criar bancos de teste).
    pub fn without_db(&self) -> PgConnectOptions {
        let ssl_mode = if self.require_ssl {
            PgSslMode::Require
        } else {
            PgSslMode::Prefer
        };
        PgConnectOptions::new()
            .host(&self.host)
            .port(self.port)
            .username(&self.username)
            .password(self.password.expose_secret())
            .ssl_mode(ssl_mode)
    }

    pub fn with_db(&self) -> PgConnectOptions {
        self.without_db().database(&self.database_name)
    }
}

#[derive(Debug, Deserialize)]
pub struct RedisSettings {
    pub url: SecretString,
    /// Prefixo de todas as chaves; permite dividir um Redis entre serviços (e testes).
    pub key_prefix: String,
}

#[derive(Debug, Deserialize)]
pub struct JwtSettings {
    pub issuer: String,
    pub audience: String,
    pub access_token_ttl_seconds: i64,
    /// Chave privada Ed25519 em PEM PKCS#8, vinda de um secret. Tem prioridade sobre o arquivo.
    pub private_key_pem: Option<SecretString>,
    /// Caminho de um arquivo PEM PKCS#8 com a chave privada.
    pub private_key_path: Option<PathBuf>,
    /// Só para desenvolvimento: gera a chave no caminho acima se ele não existir.
    pub generate_key_if_missing: bool,
}

#[derive(Debug, Deserialize)]
pub struct RefreshTokenSettings {
    pub ttl_seconds: i64,
}

#[derive(Debug, Deserialize)]
pub struct PasswordSettings {
    /// Custo de memória do Argon2id em KiB.
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

#[derive(Debug, Deserialize)]
pub struct RateLimitSettings {
    pub login_max_attempts_per_email: u32,
    pub login_max_attempts_per_ip: u32,
    pub window_seconds: u64,
    /// Só ligue atrás de um proxy confiável que sobrescreve o `X-Forwarded-For`.
    pub trust_x_forwarded_for: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TelemetrySettings {
    pub log_format: LogFormat,
    pub log_level: String,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Json,
    Pretty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Local,
    Production,
}

impl Environment {
    pub fn as_str(&self) -> &'static str {
        match self {
            Environment::Local => "local",
            Environment::Production => "production",
        }
    }
}

impl TryFrom<String> for Environment {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "local" => Ok(Self::Local),
            "production" => Ok(Self::Production),
            other => Err(format!(
                "`{other}` is not a supported environment; use `local` or `production`"
            )),
        }
    }
}

/// Carrega a configuração a partir da pasta `configuration/` do diretório atual.
pub fn get_configuration() -> Result<Settings, config::ConfigError> {
    let base_path = std::env::current_dir()
        .map_err(|e| config::ConfigError::Message(format!("cannot read current dir: {e}")))?
        .join("configuration");

    let environment: Environment = std::env::var("APP_ENVIRONMENT")
        .unwrap_or_else(|_| "local".into())
        .try_into()
        .map_err(config::ConfigError::Message)?;

    config::Config::builder()
        .add_source(config::File::from(base_path.join("base.yaml")))
        .add_source(config::File::from(
            base_path.join(format!("{}.yaml", environment.as_str())),
        ))
        .add_source(
            config::Environment::with_prefix("APP")
                .prefix_separator("_")
                .separator("__")
                .try_parsing(true),
        )
        .build()?
        .try_deserialize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_environments_case_insensitively() {
        assert_eq!(
            Environment::try_from("LOCAL".to_string()),
            Ok(Environment::Local)
        );
        assert_eq!(
            Environment::try_from("production".to_string()),
            Ok(Environment::Production)
        );
        assert!(Environment::try_from("staging".to_string()).is_err());
    }
}
