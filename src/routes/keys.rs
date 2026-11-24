use axum::Json;
use axum::extract::State;
use axum::http::{HeaderValue, header};
use axum::response::IntoResponse;

use crate::auth::AppState;
use crate::crypto::jwt::Jwks;

/// Chaves públicas para validar os access tokens sem falar com este serviço.
#[utoipa::path(
    get,
    path = "/.well-known/jwks.json",
    tag = "keys",
    responses((status = 200, description = "JSON Web Key Set (RFC 7517)", body = Jwks))
)]
pub async fn jwks(State(state): State<AppState>) -> impl IntoResponse {
    // Cache curto: quem valida tokens não precisa buscar a chave a cada request,
    // e uma rotação de chave se propaga em minutos.
    (
        [(
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=300"),
        )],
        Json(state.jwt.jwks()),
    )
}
