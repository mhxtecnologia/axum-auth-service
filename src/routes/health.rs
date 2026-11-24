use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::Serialize;
use utoipa::ToSchema;

use crate::auth::AppState;

const CHECK_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Serialize, ToSchema)]
pub struct HealthResponse {
    #[schema(example = "ok")]
    pub status: &'static str,
}

#[derive(Serialize, ToSchema)]
pub struct ReadinessResponse {
    #[schema(example = "ok")]
    pub status: &'static str,
    #[schema(example = "ok")]
    pub database: &'static str,
    #[schema(example = "ok")]
    pub redis: &'static str,
}

/// O processo está de pé (liveness). Não consulta dependências.
#[utoipa::path(
    get,
    path = "/health/live",
    tag = "health",
    responses((status = 200, description = "Process is running", body = HealthResponse))
)]
pub async fn live() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

/// Pronto para tráfego (readiness): Postgres e Redis respondendo.
#[utoipa::path(
    get,
    path = "/health/ready",
    tag = "health",
    responses(
        (status = 200, description = "All dependencies are reachable", body = ReadinessResponse),
        (status = 503, description = "At least one dependency is down", body = ReadinessResponse),
    )
)]
pub async fn ready(State(state): State<AppState>) -> (StatusCode, Json<ReadinessResponse>) {
    let mut conn = state.redis.clone();
    let database = tokio::time::timeout(CHECK_TIMEOUT, sqlx::query("SELECT 1").execute(&state.db));
    let redis = tokio::time::timeout(CHECK_TIMEOUT, async move {
        let pong: String = redis::cmd("PING").query_async(&mut conn).await?;
        Ok::<_, redis::RedisError>(pong)
    });
    let (database, redis) = tokio::join!(database, redis);

    let database_ok = matches!(database, Ok(Ok(_)));
    let redis_ok = matches!(redis, Ok(Ok(_)));
    let label = |ok: bool| if ok { "ok" } else { "unavailable" };
    let status = if database_ok && redis_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(ReadinessResponse {
            status: label(database_ok && redis_ok),
            database: label(database_ok),
            redis: label(redis_ok),
        }),
    )
}
