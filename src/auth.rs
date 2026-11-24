//! Casos de uso: cadastro, login, refresh com rotação e logout.

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::anyhow;
use chrono::{DateTime, Duration, Utc};
use redis::aio::ConnectionManager;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use crate::crypto::jwt::JwtKeys;
use crate::crypto::password::Passwords;
use crate::crypto::refresh_token;
use crate::domain::{normalize_email, validate_password};
use crate::error::AppError;
use crate::rate_limit::{Decision, LoginRateLimiter};
use crate::repository::refresh_tokens::{self, NewRefreshToken};
use crate::repository::users::{self, UserRecord};

/// Estado compartilhado por todos os handlers. Clonar é barato (tudo é `Arc` ou pool).
#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub redis: ConnectionManager,
    pub passwords: Arc<Passwords>,
    pub jwt: Arc<JwtKeys>,
    pub login_limiter: LoginRateLimiter,
    pub refresh_token_ttl: Duration,
    pub trust_x_forwarded_for: bool,
}

pub struct TokenPair {
    pub access_token: String,
    pub access_token_expires_in: i64,
    pub refresh_token: String,
    pub refresh_token_expires_in: i64,
}

pub async fn register(
    state: &AppState,
    email: &str,
    password: String,
) -> Result<UserRecord, AppError> {
    let email = normalize_email(email)?;
    validate_password(&password)?;

    let passwords = state.passwords.clone();
    let password_hash = run_blocking(move || passwords.hash(&password)).await?;

    users::insert(&state.db, Uuid::now_v7(), &email, &password_hash)
        .await?
        .ok_or(AppError::EmailTaken)
}

pub async fn login(
    state: &AppState,
    email: &str,
    password: String,
    client_ip: IpAddr,
) -> Result<TokenPair, AppError> {
    // E-mail mal formatado não é erro de validação aqui: a resposta é a mesma de
    // credencial errada, para o login não virar um oráculo de formato.
    let email = email.trim().to_lowercase();

    // Redis fora do ar fecha o login (503) em vez de liberar força bruta sem limite.
    match state
        .login_limiter
        .hit(&email, client_ip)
        .await
        .map_err(|e| AppError::Unavailable(e.into()))?
    {
        Decision::Allowed => {}
        Decision::Limited {
            retry_after_seconds,
        } => {
            return Err(AppError::TooManyRequests {
                retry_after_seconds,
            });
        }
    }

    let user = users::find_by_email(&state.db, &email).await?;
    let passwords = state.passwords.clone();
    let user = match user {
        Some(user) => {
            let hash = user.password_hash.clone();
            let valid = run_blocking(move || passwords.verify(&password, &hash)).await?;
            valid.then_some(user)
        }
        None => {
            run_blocking(move || {
                passwords.verify_dummy(&password);
                Ok::<_, AppError>(())
            })
            .await?;
            None
        }
    };
    let user = user.ok_or(AppError::InvalidCredentials)?;

    if let Err(e) = state.login_limiter.reset_email(&email).await {
        // O login já foi validado; falhar aqui só deixa o contador expirar sozinho.
        tracing::warn!(error = %e, "could not reset the login rate limit counter");
    }

    let now = Utc::now();
    let mut conn = state.db.acquire().await?;
    let pair = issue_token_pair(state, &mut conn, user.id, Uuid::now_v7(), now).await?;
    tracing::info!(user_id = %user.id, "user logged in");
    Ok(pair)
}

/// Troca um refresh token por um par novo. Cada refresh token vale **uma** vez:
/// apresentar um já usado indica roubo (o legítimo e o atacante têm a mesma
/// cópia), e a família inteira é revogada — os dois lados perdem a sessão.
pub async fn refresh(state: &AppState, presented: &str) -> Result<TokenPair, AppError> {
    let now = Utc::now();
    let mut tx = state.db.begin().await?;

    let Some(token) =
        refresh_tokens::find_by_hash_for_update(&mut tx, &refresh_token::hash(presented)).await?
    else {
        return Err(AppError::InvalidRefreshToken);
    };

    if token.used_at.is_some() {
        let revoked = refresh_tokens::revoke_family(&mut tx, token.family_id, now).await?;
        // A revogação precisa ser gravada antes de responder com o erro.
        tx.commit().await?;
        tracing::warn!(
            family_id = %token.family_id,
            user_id = %token.user_id,
            revoked,
            "refresh token reused; session family revoked"
        );
        return Err(AppError::RefreshTokenReused);
    }
    if token.revoked_at.is_some() || token.expires_at <= now {
        return Err(AppError::InvalidRefreshToken);
    }

    let pair =
        issue_token_pair_with_id(state, &mut tx, token.user_id, token.family_id, now).await?;
    refresh_tokens::mark_used(&mut tx, token.id, pair.1, now).await?;
    tx.commit().await?;
    Ok(pair.0)
}

/// Encerra a sessão do refresh token informado. Sempre bem-sucedido do ponto de
/// vista do cliente: token desconhecido não revela nada.
pub async fn logout(state: &AppState, presented: &str) -> Result<(), AppError> {
    let now = Utc::now();
    let mut tx = state.db.begin().await?;
    if let Some(token) =
        refresh_tokens::find_by_hash_for_update(&mut tx, &refresh_token::hash(presented)).await?
    {
        refresh_tokens::revoke_family(&mut tx, token.family_id, now).await?;
        tracing::info!(user_id = %token.user_id, "user logged out");
    }
    tx.commit().await?;
    Ok(())
}

pub async fn find_user(state: &AppState, id: Uuid) -> Result<UserRecord, AppError> {
    // Token válido de um usuário que não existe mais: trata como não autenticado.
    users::find_by_id(&state.db, id)
        .await?
        .ok_or(AppError::Unauthorized)
}

async fn issue_token_pair(
    state: &AppState,
    conn: &mut PgConnection,
    user_id: Uuid,
    family_id: Uuid,
    now: DateTime<Utc>,
) -> Result<TokenPair, AppError> {
    Ok(
        issue_token_pair_with_id(state, conn, user_id, family_id, now)
            .await?
            .0,
    )
}

/// Emite o par e devolve também o id do refresh token novo (usado no `replaced_by`).
async fn issue_token_pair_with_id(
    state: &AppState,
    conn: &mut PgConnection,
    user_id: Uuid,
    family_id: Uuid,
    now: DateTime<Utc>,
) -> Result<(TokenPair, Uuid), AppError> {
    let access_token = state
        .jwt
        .issue(user_id, now)
        .map_err(|e| AppError::Internal(anyhow!("cannot sign access token: {e}")))?;
    let refresh = refresh_token::generate()
        .map_err(|e| AppError::Internal(anyhow!("OS random generator failed: {e}")))?;
    let id = Uuid::now_v7();

    refresh_tokens::insert(
        conn,
        NewRefreshToken {
            id,
            user_id,
            family_id,
            token_hash: &refresh.hash,
            expires_at: now + state.refresh_token_ttl,
        },
    )
    .await?;

    Ok((
        TokenPair {
            access_token,
            access_token_expires_in: state.jwt.access_token_ttl_seconds(),
            refresh_token: refresh.plaintext,
            refresh_token_expires_in: state.refresh_token_ttl.num_seconds(),
        },
        id,
    ))
}

/// Roda trabalho de CPU (Argon2) fora das threads do runtime assíncrono.
async fn run_blocking<T, E, F>(work: F) -> Result<T, AppError>
where
    F: FnOnce() -> Result<T, E> + Send + 'static,
    T: Send + 'static,
    E: Into<AppError> + Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| AppError::Internal(anyhow!("blocking task failed: {e}")))?
        .map_err(Into::into)
}
