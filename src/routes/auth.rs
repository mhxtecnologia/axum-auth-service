use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{self as service, AppState, TokenPair};
use crate::error::{AppError, AppJson, ErrorBody};
use crate::extract::ClientIp;
use crate::routes::users::UserResponse;

// Sem `Debug` nos corpos com senha/token: nada disso pode acabar num log por acidente.
#[derive(Deserialize, ToSchema)]
pub struct CredentialsRequest {
    #[schema(example = "ada@example.com")]
    pub email: String,
    #[schema(example = "correct horse battery staple")]
    pub password: String,
}

#[derive(Deserialize, ToSchema)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Serialize, ToSchema)]
pub struct TokenResponse {
    /// JWT assinado com Ed25519; valide com a chave de `/.well-known/jwks.json`.
    pub access_token: String,
    #[schema(example = "Bearer")]
    pub token_type: &'static str,
    /// Validade do access token, em segundos.
    #[schema(example = 900)]
    pub expires_in: i64,
    /// Token opaco de uso único; cada refresh devolve um novo.
    pub refresh_token: String,
    #[schema(example = 2592000)]
    pub refresh_token_expires_in: i64,
}

impl From<TokenPair> for TokenResponse {
    fn from(pair: TokenPair) -> Self {
        Self {
            access_token: pair.access_token,
            token_type: "Bearer",
            expires_in: pair.access_token_expires_in,
            refresh_token: pair.refresh_token,
            refresh_token_expires_in: pair.refresh_token_expires_in,
        }
    }
}

/// Cria uma conta.
#[utoipa::path(
    post,
    path = "/auth/register",
    tag = "auth",
    request_body = CredentialsRequest,
    responses(
        (status = 201, description = "Account created", body = UserResponse),
        (status = 400, description = "Malformed JSON body", body = ErrorBody),
        (status = 409, description = "Email already registered", body = ErrorBody),
        (status = 422, description = "Invalid email or weak password", body = ErrorBody),
    )
)]
pub async fn register(
    State(state): State<AppState>,
    AppJson(body): AppJson<CredentialsRequest>,
) -> Result<(StatusCode, Json<UserResponse>), AppError> {
    let user = service::register(&state, &body.email, body.password).await?;
    Ok((StatusCode::CREATED, Json(user.into())))
}

/// Autentica e devolve um access token e um refresh token.
#[utoipa::path(
    post,
    path = "/auth/login",
    tag = "auth",
    request_body = CredentialsRequest,
    responses(
        (status = 200, description = "Authenticated", body = TokenResponse),
        (status = 401, description = "Wrong email or password", body = ErrorBody),
        (status = 429, description = "Too many attempts; see the Retry-After header", body = ErrorBody),
        (status = 503, description = "Rate limiter unavailable", body = ErrorBody),
    )
)]
pub async fn login(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AppJson(body): AppJson<CredentialsRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    let pair = service::login(&state, &body.email, body.password, ip).await?;
    Ok(Json(pair.into()))
}

/// Troca o refresh token por um par novo (rotação). Reusar um token revoga a sessão.
#[utoipa::path(
    post,
    path = "/auth/refresh",
    tag = "auth",
    request_body = RefreshTokenRequest,
    responses(
        (status = 200, description = "New token pair", body = TokenResponse),
        (status = 401, description = "Invalid, expired or reused refresh token", body = ErrorBody),
    )
)]
pub async fn refresh(
    State(state): State<AppState>,
    AppJson(body): AppJson<RefreshTokenRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    let pair = service::refresh(&state, &body.refresh_token).await?;
    Ok(Json(pair.into()))
}

/// Encerra a sessão do refresh token informado.
#[utoipa::path(
    post,
    path = "/auth/logout",
    tag = "auth",
    request_body = RefreshTokenRequest,
    responses((status = 204, description = "Session closed (also for unknown tokens)"))
)]
pub async fn logout(
    State(state): State<AppState>,
    AppJson(body): AppJson<RefreshTokenRequest>,
) -> Result<StatusCode, AppError> {
    service::logout(&state, &body.refresh_token).await?;
    Ok(StatusCode::NO_CONTENT)
}
