use axum::Json;
use axum::extract::State;
use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::{self as service, AppState};
use crate::error::{AppError, ErrorBody};
use crate::extract::AuthenticatedUser;
use crate::repository::users::UserRecord;

#[derive(Serialize, ToSchema)]
pub struct UserResponse {
    pub id: Uuid,
    #[schema(example = "ada@example.com")]
    pub email: String,
    pub created_at: DateTime<Utc>,
}

impl From<UserRecord> for UserResponse {
    fn from(user: UserRecord) -> Self {
        Self {
            id: user.id,
            email: user.email,
            created_at: user.created_at,
        }
    }
}

/// Dados do usuário dono do access token.
#[utoipa::path(
    get,
    path = "/users/me",
    tag = "users",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Current user", body = UserResponse),
        (status = 401, description = "Missing, invalid or expired access token", body = ErrorBody),
    )
)]
pub async fn me(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<UserResponse>, AppError> {
    Ok(Json(service::find_user(&state, user.user_id).await?.into()))
}
