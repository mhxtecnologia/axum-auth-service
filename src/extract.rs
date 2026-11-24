//! Extratores próprios: usuário autenticado por Bearer e IP do cliente.

use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use chrono::Utc;
use uuid::Uuid;

use crate::auth::AppState;
use crate::error::AppError;

/// Usuário dono de um JWT de acesso válido (`Authorization: Bearer <token>`).
pub struct AuthenticatedUser {
    pub user_id: Uuid,
}

impl FromRequestParts<AppState> for AuthenticatedUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or(AppError::Unauthorized)?;
        // O esquema é case-insensitive (RFC 9110); o token em si não.
        let (scheme, token) = header.split_once(' ').ok_or(AppError::Unauthorized)?;
        if !scheme.eq_ignore_ascii_case("bearer") {
            return Err(AppError::Unauthorized);
        }
        let claims = state
            .jwt
            .verify(token.trim(), Utc::now())
            .map_err(|_| AppError::Unauthorized)?;
        Ok(Self {
            user_id: claims.sub,
        })
    }
}

/// IP do cliente para o rate limit. Por padrão é o endereço da conexão TCP;
/// o `X-Forwarded-For` só é lido quando a configuração diz que há um proxy
/// confiável na frente — senão qualquer cliente forjaria o próprio IP.
pub struct ClientIp(pub IpAddr);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        if state.trust_x_forwarded_for {
            // O proxy acrescenta o IP que viu no fim da lista; é o único confiável.
            let forwarded = parts
                .headers
                .get_all("x-forwarded-for")
                .iter()
                .filter_map(|value| value.to_str().ok())
                .flat_map(|value| value.split(','))
                .next_back()
                .and_then(|ip| ip.trim().parse::<IpAddr>().ok());
            if let Some(ip) = forwarded {
                return Ok(Self(ip));
            }
        }
        let ConnectInfo(addr) = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .copied()
            .ok_or_else(|| {
                AppError::Internal(anyhow::anyhow!("missing ConnectInfo<SocketAddr>"))
            })?;
        Ok(Self(addr.ip()))
    }
}
