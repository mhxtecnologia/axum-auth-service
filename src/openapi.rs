//! Documento OpenAPI 3.1 gerado a partir dos handlers (utoipa), servido com Swagger UI.

use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

use crate::routes;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "axum-auth-service",
        description = "Authentication service: Argon2id passwords, Ed25519-signed JWTs \
                       published as JWKS, and rotating refresh tokens with reuse detection."
    ),
    paths(
        routes::auth::register,
        routes::auth::login,
        routes::auth::refresh,
        routes::auth::logout,
        routes::users::me,
        routes::keys::jwks,
        routes::health::live,
        routes::health::ready,
    ),
    modifiers(&BearerAuth),
    tags(
        (name = "auth", description = "Registration, login and session lifecycle"),
        (name = "users", description = "Endpoints that require an access token"),
        (name = "keys", description = "Public keys for offline token validation"),
        (name = "health", description = "Liveness and readiness probes"),
    )
)]
pub struct ApiDoc;

/// Registra o esquema `bearer` usado por `security(("bearer" = []))` nos handlers.
struct BearerAuth;

impl Modify for BearerAuth {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build(),
            ),
        );
    }
}
