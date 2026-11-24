//! Monta as dependências, o roteador e o servidor HTTP.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::Router;
use axum::extract::{DefaultBodyLimit, Request};
use axum::routing::{get, post};
use secrecy::ExposeSecret;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::{DefaultOnResponse, TraceLayer};
use tracing::{Level, Span};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::auth::AppState;
use crate::configuration::{DatabaseSettings, Settings};
use crate::crypto::jwt::JwtKeys;
use crate::crypto::password::Passwords;
use crate::openapi::ApiDoc;
use crate::rate_limit::LoginRateLimiter;
use crate::routes;

/// Os corpos aceitos são JSONs pequenos; 16 KiB sobra e corta abuso de memória.
const MAX_BODY_BYTES: usize = 16 * 1024;

pub struct Application {
    port: u16,
    listener: TcpListener,
    router: Router,
}

impl Application {
    pub async fn build(settings: Settings) -> anyhow::Result<Self> {
        let db = get_connection_pool(&settings.database);
        if settings.database.run_migrations {
            sqlx::migrate!("./migrations")
                .run(&db)
                .await
                .context("failed to run database migrations")?;
        }

        let redis = redis::Client::open(settings.redis.url.expose_secret())
            .context("invalid Redis URL")?
            .get_connection_manager()
            .await
            .context("failed to connect to Redis")?;

        let jwt = JwtKeys::from_settings(&settings.jwt)?;
        let passwords = Passwords::new(&settings.password)?;
        let state = AppState {
            db,
            login_limiter: LoginRateLimiter::new(
                redis.clone(),
                &settings.redis.key_prefix,
                &settings.rate_limit,
            ),
            redis,
            passwords: Arc::new(passwords),
            jwt: Arc::new(jwt),
            refresh_token_ttl: chrono::Duration::seconds(settings.refresh_token.ttl_seconds),
            trust_x_forwarded_for: settings.rate_limit.trust_x_forwarded_for,
        };

        let address = format!(
            "{}:{}",
            settings.application.host, settings.application.port
        );
        let listener = TcpListener::bind(&address)
            .await
            .with_context(|| format!("cannot bind {address}"))?;
        let port = listener.local_addr()?.port();

        Ok(Self {
            port,
            listener,
            router: build_router(state),
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub async fn run_until_stopped(self) -> std::io::Result<()> {
        axum::serve(
            self.listener,
            self.router
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal())
        .await
    }
}

pub fn get_connection_pool(settings: &DatabaseSettings) -> PgPool {
    PgPoolOptions::new()
        .max_connections(settings.max_connections)
        .acquire_timeout(Duration::from_secs(5))
        .connect_lazy_with(settings.with_db())
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/auth/register", post(routes::auth::register))
        .route("/auth/login", post(routes::auth::login))
        .route("/auth/refresh", post(routes::auth::refresh))
        .route("/auth/logout", post(routes::auth::logout))
        .route("/users/me", get(routes::users::me))
        .route("/.well-known/jwks.json", get(routes::keys::jwks))
        .route("/health/live", get(routes::health::live))
        .route("/health/ready", get(routes::health::ready))
        .merge(SwaggerUi::new("/docs").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(
            // Ordem de fora para dentro: gera o id, abre o span com ele e o devolve na resposta.
            // Um `x-request-id` enviado pelo cliente é mantido, para rastrear entre serviços.
            ServiceBuilder::new()
                .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
                .layer(
                    TraceLayer::new_for_http()
                        .make_span_with(request_span)
                        .on_response(DefaultOnResponse::new().level(Level::INFO)),
                )
                .layer(PropagateRequestIdLayer::x_request_id()),
        )
        .with_state(state)
}

fn request_span(request: &Request) -> Span {
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("-");
    // Só o path: a query string poderia carregar dado sensível.
    tracing::info_span!(
        "http_request",
        method = %request.method(),
        path = %request.uri().path(),
        request_id = %request_id,
    )
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("shutdown signal received; draining connections");
}
