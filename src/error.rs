//! Erro único da API, convertido em JSON `{ "error": { "code", "message" } }`.

use axum::extract::rejection::JsonRejection;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    Validation(String),
    /// Rejeição do extrator JSON; mantém o status dele (400, 413, 415 ou 422).
    #[error("request body is invalid: {message}")]
    InvalidBody { status: StatusCode, message: String },
    #[error("email is already registered")]
    EmailTaken,
    #[error("invalid email or password")]
    InvalidCredentials,
    #[error("refresh token is invalid or expired")]
    InvalidRefreshToken,
    #[error("refresh token was already used; the whole session was revoked")]
    RefreshTokenReused,
    #[error("missing or invalid access token")]
    Unauthorized,
    #[error("too many login attempts; try again later")]
    TooManyRequests { retry_after_seconds: u64 },
    #[error("a dependency is unavailable; try again later")]
    Unavailable(#[source] anyhow::Error),
    #[error("internal server error")]
    Internal(#[source] anyhow::Error),
}

#[derive(Serialize, ToSchema)]
pub struct ErrorBody {
    pub error: ErrorDetail,
}

#[derive(Serialize, ToSchema)]
pub struct ErrorDetail {
    /// Código estável, para o cliente decidir o que fazer sem ler a mensagem.
    #[schema(example = "invalid_credentials")]
    pub code: &'static str,
    #[schema(example = "invalid email or password")]
    pub message: String,
}

impl AppError {
    fn status_and_code(&self) -> (StatusCode, &'static str) {
        match self {
            Self::Validation(_) => (StatusCode::UNPROCESSABLE_ENTITY, "validation_error"),
            Self::InvalidBody { status, .. } if *status == StatusCode::PAYLOAD_TOO_LARGE => {
                (*status, "payload_too_large")
            }
            Self::InvalidBody { status, .. } => (*status, "invalid_body"),
            Self::EmailTaken => (StatusCode::CONFLICT, "email_taken"),
            Self::InvalidCredentials => (StatusCode::UNAUTHORIZED, "invalid_credentials"),
            Self::InvalidRefreshToken => (StatusCode::UNAUTHORIZED, "invalid_refresh_token"),
            Self::RefreshTokenReused => (StatusCode::UNAUTHORIZED, "refresh_token_reused"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::TooManyRequests { .. } => (StatusCode::TOO_MANY_REQUESTS, "too_many_requests"),
            Self::Unavailable(_) => (StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
            Self::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code) = self.status_and_code();
        // A causa detalhada vai só para o log; o cliente recebe a mensagem genérica.
        match &self {
            Self::Internal(source) => tracing::error!(error = ?source, "request failed"),
            Self::Unavailable(source) => tracing::warn!(error = ?source, "dependency unavailable"),
            Self::RefreshTokenReused => tracing::warn!("refresh token reuse detected"),
            _ => {}
        }

        let body = ErrorBody {
            error: ErrorDetail {
                code,
                message: self.to_string(),
            },
        };
        let mut response = (status, axum::Json(body)).into_response();
        let headers = response.headers_mut();
        match &self {
            Self::TooManyRequests {
                retry_after_seconds,
            } => {
                headers.insert(header::RETRY_AFTER, HeaderValue::from(*retry_after_seconds));
            }
            Self::Unauthorized => {
                headers.insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
            }
            _ => {}
        }
        response
    }
}

impl From<JsonRejection> for AppError {
    fn from(rejection: JsonRejection) -> Self {
        Self::InvalidBody {
            status: rejection.status(),
            message: rejection.body_text(),
        }
    }
}

impl From<sqlx::Error> for AppError {
    fn from(error: sqlx::Error) -> Self {
        Self::Internal(error.into())
    }
}

impl From<crate::crypto::password::PasswordError> for AppError {
    fn from(error: crate::crypto::password::PasswordError) -> Self {
        Self::Internal(error.into())
    }
}

/// `Json` com rejeição no mesmo formato de erro do resto da API.
#[derive(axum::extract::FromRequest)]
#[from_request(via(axum::Json), rejection(AppError))]
pub struct AppJson<T>(pub T);
