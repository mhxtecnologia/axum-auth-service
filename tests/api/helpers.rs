//! Sobe uma instância real do serviço por teste: banco Postgres novo (com as
//! migrations), prefixo de chaves próprio no Redis e porta aleatória.

use std::sync::LazyLock;

use axum_auth_service::configuration::{LogFormat, Settings, TelemetrySettings, get_configuration};
use axum_auth_service::crypto::jwt::{generate_signing_key, signing_key_to_pem};
use axum_auth_service::startup::{Application, get_connection_pool};
use axum_auth_service::telemetry::init_subscriber;
use reqwest::Response;
use serde_json::{Value, json};
use sqlx::{Connection, Executor, PgConnection, PgPool};
use uuid::Uuid;

pub const PASSWORD: &str = "correct horse battery staple";

/// Logs dos testes só com `TEST_LOG=1`, para não poluir a saída do `cargo test`.
static TRACING: LazyLock<()> = LazyLock::new(|| {
    if std::env::var("TEST_LOG").is_ok() {
        init_subscriber(&TelemetrySettings {
            log_format: LogFormat::Pretty,
            log_level: "debug".into(),
        });
    }
});

pub struct TestApp {
    pub address: String,
    pub client: reqwest::Client,
    pub db: PgPool,
}

pub async fn spawn_app() -> TestApp {
    spawn_app_with(|_| {}).await
}

pub async fn spawn_app_with(customize: impl FnOnce(&mut Settings)) -> TestApp {
    LazyLock::force(&TRACING);

    let mut settings = get_configuration().expect("failed to load configuration");
    settings.application.host = "127.0.0.1".into();
    settings.application.port = 0;
    settings.database.database_name = format!("test_{}", Uuid::new_v4().simple());
    settings.redis.key_prefix = format!("test:{}:", Uuid::new_v4().simple());
    settings.jwt.private_key_pem = Some(
        signing_key_to_pem(&generate_signing_key().unwrap())
            .unwrap()
            .into(),
    );
    // Argon2 barato nos testes; produção usa os parâmetros da OWASP.
    settings.password.memory_kib = 1024;
    settings.password.iterations = 1;
    customize(&mut settings);

    let mut admin = PgConnection::connect_with(&settings.database.without_db())
        .await
        .expect("Postgres is not reachable; run `docker compose up -d postgres redis`");
    admin
        .execute(format!(r#"CREATE DATABASE "{}""#, settings.database.database_name).as_str())
        .await
        .expect("failed to create the test database");
    let db = get_connection_pool(&settings.database);

    let application = Application::build(settings)
        .await
        .expect("failed to build the application");
    let address = format!("http://127.0.0.1:{}", application.port());
    tokio::spawn(application.run_until_stopped());

    TestApp {
        address,
        client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
        db,
    }
}

pub fn unique_email() -> String {
    format!("user-{}@example.com", Uuid::new_v4().simple())
}

impl TestApp {
    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.address)
    }

    pub async fn post_json(&self, path: &str, body: &Value) -> Response {
        self.client
            .post(self.url(path))
            .json(body)
            .send()
            .await
            .expect("request failed")
    }

    pub async fn register(&self, email: &str, password: &str) -> Response {
        self.post_json(
            "/auth/register",
            &json!({ "email": email, "password": password }),
        )
        .await
    }

    pub async fn login(&self, email: &str, password: &str) -> Response {
        self.post_json(
            "/auth/login",
            &json!({ "email": email, "password": password }),
        )
        .await
    }

    pub async fn refresh(&self, refresh_token: &str) -> Response {
        self.post_json("/auth/refresh", &json!({ "refresh_token": refresh_token }))
            .await
    }

    pub async fn logout(&self, refresh_token: &str) -> Response {
        self.post_json("/auth/logout", &json!({ "refresh_token": refresh_token }))
            .await
    }

    pub async fn me(&self, access_token: &str) -> Response {
        self.client
            .get(self.url("/users/me"))
            .bearer_auth(access_token)
            .send()
            .await
            .expect("request failed")
    }

    /// Cadastra um usuário novo e faz login; devolve o e-mail e o corpo do login.
    pub async fn signed_in_user(&self) -> (String, Value) {
        let email = unique_email();
        assert_eq!(self.register(&email, PASSWORD).await.status(), 201);
        let response = self.login(&email, PASSWORD).await;
        assert_eq!(response.status(), 200);
        (email, response.json().await.unwrap())
    }
}

/// Lê o `error.code` do corpo de erro padrão da API.
pub async fn error_code(response: Response) -> String {
    let body: Value = response.json().await.expect("error body is not JSON");
    body["error"]["code"]
        .as_str()
        .expect("missing error.code")
        .to_owned()
}
