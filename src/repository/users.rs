use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

#[derive(Debug, FromRow)]
pub struct UserRecord {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
}

/// Erro de unicidade do e-mail vira `Ok(None)`; o resto sobe como erro do banco.
pub async fn insert(
    pool: &PgPool,
    id: Uuid,
    email: &str,
    password_hash: &str,
) -> Result<Option<UserRecord>, sqlx::Error> {
    let result = sqlx::query_as::<_, UserRecord>(
        "INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3) \
         RETURNING id, email, password_hash, created_at",
    )
    .bind(id)
    .bind(email)
    .bind(password_hash)
    .fetch_one(pool)
    .await;

    match result {
        Ok(user) => Ok(Some(user)),
        Err(sqlx::Error::Database(db)) if db.is_unique_violation() => Ok(None),
        Err(e) => Err(e),
    }
}

pub async fn find_by_email(pool: &PgPool, email: &str) -> Result<Option<UserRecord>, sqlx::Error> {
    sqlx::query_as::<_, UserRecord>(
        "SELECT id, email, password_hash, created_at FROM users WHERE email = $1",
    )
    .bind(email)
    .fetch_optional(pool)
    .await
}

pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<UserRecord>, sqlx::Error> {
    sqlx::query_as::<_, UserRecord>(
        "SELECT id, email, password_hash, created_at FROM users WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}
