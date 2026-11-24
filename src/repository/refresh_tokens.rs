use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgConnection};
use uuid::Uuid;

#[derive(Debug, FromRow)]
pub struct RefreshTokenRecord {
    pub id: Uuid,
    pub user_id: Uuid,
    pub family_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

pub struct NewRefreshToken<'a> {
    pub id: Uuid,
    pub user_id: Uuid,
    /// Todos os tokens nascidos do mesmo login compartilham a família.
    pub family_id: Uuid,
    pub token_hash: &'a [u8],
    pub expires_at: DateTime<Utc>,
}

pub async fn insert(
    conn: &mut PgConnection,
    token: NewRefreshToken<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO refresh_tokens (id, user_id, family_id, token_hash, expires_at) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(token.id)
    .bind(token.user_id)
    .bind(token.family_id)
    .bind(token.token_hash)
    .bind(token.expires_at)
    .execute(conn)
    .await?;
    Ok(())
}

/// Busca o token travando a linha (`FOR UPDATE`): dois refresh simultâneos com
/// o mesmo token são serializados, e o segundo enxerga o primeiro já usado.
pub async fn find_by_hash_for_update(
    conn: &mut PgConnection,
    token_hash: &[u8],
) -> Result<Option<RefreshTokenRecord>, sqlx::Error> {
    sqlx::query_as::<_, RefreshTokenRecord>(
        "SELECT id, user_id, family_id, expires_at, used_at, revoked_at \
         FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE",
    )
    .bind(token_hash)
    .fetch_optional(conn)
    .await
}

pub async fn mark_used(
    conn: &mut PgConnection,
    id: Uuid,
    replaced_by: Uuid,
    now: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE refresh_tokens SET used_at = $2, replaced_by = $3 WHERE id = $1")
        .bind(id)
        .bind(now)
        .bind(replaced_by)
        .execute(conn)
        .await?;
    Ok(())
}

/// Revoga a família inteira: encerra a sessão em todos os tokens derivados dela.
pub async fn revoke_family(
    conn: &mut PgConnection,
    family_id: Uuid,
    now: DateTime<Utc>,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = $2 WHERE family_id = $1 AND revoked_at IS NULL",
    )
    .bind(family_id)
    .bind(now)
    .execute(conn)
    .await?;
    Ok(result.rows_affected())
}
