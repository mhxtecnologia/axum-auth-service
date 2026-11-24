use serde_json::Value;

use crate::helpers::{error_code, spawn_app};

fn field<'a>(body: &'a Value, name: &str) -> &'a str {
    body[name].as_str().unwrap()
}

#[tokio::test]
async fn refresh_rotates_both_tokens() {
    let app = spawn_app().await;
    let (_, first) = app.signed_in_user().await;

    let response = app.refresh(field(&first, "refresh_token")).await;

    assert_eq!(response.status(), 200);
    let second: Value = response.json().await.unwrap();
    assert_ne!(
        field(&second, "refresh_token"),
        field(&first, "refresh_token")
    );
    assert_eq!(app.me(field(&second, "access_token")).await.status(), 200);
}

#[tokio::test]
async fn reusing_a_rotated_token_revokes_the_whole_session() {
    let app = spawn_app().await;
    let (_, first) = app.signed_in_user().await;
    let stolen = field(&first, "refresh_token").to_owned();

    // O cliente legítimo renova normalmente...
    let rotated: Value = app.refresh(&stolen).await.json().await.unwrap();
    // ...e depois alguém apresenta o token antigo.
    let reuse = app.refresh(&stolen).await;
    assert_eq!(reuse.status(), 401);
    assert_eq!(error_code(reuse).await, "refresh_token_reused");

    // A família inteira caiu: nem o token mais novo vale mais.
    let after = app.refresh(field(&rotated, "refresh_token")).await;
    assert_eq!(after.status(), 401);
    assert_eq!(error_code(after).await, "invalid_refresh_token");

    let (active,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM refresh_tokens WHERE revoked_at IS NULL")
            .fetch_one(&app.db)
            .await
            .unwrap();
    assert_eq!(active, 0);
}

#[tokio::test]
async fn reuse_in_one_session_does_not_touch_other_sessions() {
    let app = spawn_app().await;
    let (email, first_device) = app.signed_in_user().await;
    let second_device: Value = app
        .login(&email, crate::helpers::PASSWORD)
        .await
        .json()
        .await
        .unwrap();

    let stolen = field(&first_device, "refresh_token");
    app.refresh(stolen).await;
    app.refresh(stolen).await;

    assert_eq!(
        app.refresh(field(&second_device, "refresh_token"))
            .await
            .status(),
        200
    );
}

#[tokio::test]
async fn unknown_and_expired_refresh_tokens_are_rejected() {
    let app = spawn_app().await;
    let unknown = app.refresh("not-a-real-token").await;
    assert_eq!(unknown.status(), 401);
    assert_eq!(error_code(unknown).await, "invalid_refresh_token");

    let (_, tokens) = app.signed_in_user().await;
    sqlx::query("UPDATE refresh_tokens SET expires_at = now() - interval '1 second'")
        .execute(&app.db)
        .await
        .unwrap();
    let expired = app.refresh(field(&tokens, "refresh_token")).await;
    assert_eq!(expired.status(), 401);
    assert_eq!(error_code(expired).await, "invalid_refresh_token");
}

#[tokio::test]
async fn logout_ends_the_session() {
    let app = spawn_app().await;
    let (_, tokens) = app.signed_in_user().await;
    let refresh_token = field(&tokens, "refresh_token");

    assert_eq!(app.logout(refresh_token).await.status(), 204);

    let response = app.refresh(refresh_token).await;
    assert_eq!(response.status(), 401);
    assert_eq!(error_code(response).await, "invalid_refresh_token");
}

#[tokio::test]
async fn logout_with_an_unknown_token_reveals_nothing() {
    let app = spawn_app().await;
    assert_eq!(app.logout("not-a-real-token").await.status(), 204);
}

#[tokio::test]
async fn only_the_hash_of_the_refresh_token_is_stored() {
    let app = spawn_app().await;
    let (_, tokens) = app.signed_in_user().await;
    let refresh_token = field(&tokens, "refresh_token");

    let (stored,): (Vec<u8>,) = sqlx::query_as("SELECT token_hash FROM refresh_tokens")
        .fetch_one(&app.db)
        .await
        .unwrap();

    assert_eq!(
        stored,
        axum_auth_service::crypto::refresh_token::hash(refresh_token)
    );
    assert_ne!(stored, refresh_token.as_bytes());
}
