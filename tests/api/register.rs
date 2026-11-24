use serde_json::{Value, json};

use crate::helpers::{PASSWORD, error_code, spawn_app, unique_email};

#[tokio::test]
async fn register_creates_a_user_and_never_returns_the_hash() {
    let app = spawn_app().await;
    let email = unique_email();

    let response = app.register(&email, PASSWORD).await;

    assert_eq!(response.status(), 201);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["email"], email);
    assert!(body["id"].is_string());
    assert!(body.get("password_hash").is_none());

    let (stored,): (String,) = sqlx::query_as("SELECT password_hash FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert!(stored.starts_with("$argon2id$"), "{stored}");
}

#[tokio::test]
async fn email_is_normalized_so_duplicates_differing_in_case_conflict() {
    let app = spawn_app().await;
    let email = unique_email();
    assert_eq!(app.register(&email, PASSWORD).await.status(), 201);

    let response = app
        .register(&format!("  {}  ", email.to_uppercase()), PASSWORD)
        .await;

    assert_eq!(response.status(), 409);
    assert_eq!(error_code(response).await, "email_taken");
}

#[tokio::test]
async fn invalid_email_or_short_password_is_rejected() {
    let app = spawn_app().await;
    for (email, password) in [
        ("not-an-email", PASSWORD),
        ("ada@example", PASSWORD),
        ("ada@example.com", "too short"),
    ] {
        let response = app.register(email, password).await;
        assert_eq!(response.status(), 422, "{email} / {password}");
        assert_eq!(error_code(response).await, "validation_error");
    }
}

#[tokio::test]
async fn malformed_body_gets_the_standard_error_shape() {
    let app = spawn_app().await;

    let missing_field = app
        .post_json("/auth/register", &json!({ "email": "ada@example.com" }))
        .await;
    // JSON válido que não bate com o esquema: 422, como o extrator do axum define.
    assert_eq!(missing_field.status(), 422);
    assert_eq!(error_code(missing_field).await, "invalid_body");

    let not_json = app
        .client
        .post(app.url("/auth/register"))
        .header("content-type", "application/json")
        .body("{not json")
        .send()
        .await
        .unwrap();
    assert_eq!(not_json.status(), 400);
    assert_eq!(error_code(not_json).await, "invalid_body");
}

#[tokio::test]
async fn oversized_body_is_refused_before_parsing() {
    let app = spawn_app().await;
    let huge = "a".repeat(64 * 1024);

    let response = app
        .post_json(
            "/auth/register",
            &json!({ "email": "ada@example.com", "password": huge }),
        )
        .await;

    assert_eq!(response.status(), 413);
    assert_eq!(error_code(response).await, "payload_too_large");
}
