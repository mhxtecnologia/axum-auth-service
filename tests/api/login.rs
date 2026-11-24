use serde_json::Value;

use crate::helpers::{PASSWORD, error_code, spawn_app, unique_email};

#[tokio::test]
async fn login_returns_a_bearer_access_token_and_a_refresh_token() {
    let app = spawn_app().await;
    let (_, tokens) = app.signed_in_user().await;

    assert_eq!(tokens["token_type"], "Bearer");
    assert_eq!(tokens["expires_in"], 900);
    assert_eq!(
        tokens["access_token"].as_str().unwrap().split('.').count(),
        3
    );
    assert_eq!(tokens["refresh_token"].as_str().unwrap().len(), 43);
}

#[tokio::test]
async fn login_accepts_the_email_in_any_case() {
    let app = spawn_app().await;
    let email = unique_email();
    app.register(&email, PASSWORD).await;

    let response = app.login(&email.to_uppercase(), PASSWORD).await;

    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn wrong_password_and_unknown_email_get_the_same_answer() {
    let app = spawn_app().await;
    let email = unique_email();
    app.register(&email, PASSWORD).await;

    let wrong_password = app.login(&email, "a different long password").await;
    let unknown_email = app.login(&unique_email(), PASSWORD).await;

    assert_eq!(wrong_password.status(), 401);
    assert_eq!(unknown_email.status(), 401);
    let wrong_password: Value = wrong_password.json().await.unwrap();
    let unknown_email: Value = unknown_email.json().await.unwrap();
    assert_eq!(wrong_password, unknown_email);
    assert_eq!(wrong_password["error"]["code"], "invalid_credentials");
}

#[tokio::test]
async fn access_token_authenticates_the_user() {
    let app = spawn_app().await;
    let (email, tokens) = app.signed_in_user().await;

    let response = app.me(tokens["access_token"].as_str().unwrap()).await;

    assert_eq!(response.status(), 200);
    let me: Value = response.json().await.unwrap();
    assert_eq!(me["email"], email);
}

#[tokio::test]
async fn protected_route_rejects_missing_and_forged_tokens() {
    let app = spawn_app().await;
    let (_, tokens) = app.signed_in_user().await;
    let token = tokens["access_token"].as_str().unwrap();

    let missing = app.client.get(app.url("/users/me")).send().await.unwrap();
    assert_eq!(missing.status(), 401);
    assert_eq!(missing.headers()["www-authenticate"], "Bearer");
    assert_eq!(error_code(missing).await, "unauthorized");

    // Troca um caractere da assinatura: o token continua bem formado, mas não confere.
    // (Longe do último caractere, cujos bits finais são só padding do base64.)
    let mut forged: Vec<char> = token.chars().collect();
    let index = forged.len() - 10;
    forged[index] = if forged[index] == 'A' { 'B' } else { 'A' };
    let forged: String = forged.into_iter().collect();
    assert_eq!(app.me(&forged).await.status(), 401);

    // Um refresh token não serve como access token.
    let refresh = tokens["refresh_token"].as_str().unwrap();
    assert_eq!(app.me(refresh).await.status(), 401);
}
