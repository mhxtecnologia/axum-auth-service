//! Valida o access token como um serviço terceiro faria: só com o JWKS público.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;

use crate::helpers::spawn_app;

#[tokio::test]
async fn jwks_publishes_an_ed25519_key_with_cache_headers() {
    let app = spawn_app().await;

    let response = app
        .client
        .get(app.url("/.well-known/jwks.json"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["cache-control"], "public, max-age=300");
    let jwks: Value = response.json().await.unwrap();
    let key = &jwks["keys"][0];
    assert_eq!(key["kty"], "OKP");
    assert_eq!(key["crv"], "Ed25519");
    assert_eq!(key["alg"], "EdDSA");
    assert_eq!(key["use"], "sig");
    assert!(
        key.get("d").is_none(),
        "the private key must never be published"
    );
}

#[tokio::test]
async fn access_token_verifies_offline_with_the_published_key() {
    let app = spawn_app().await;
    let (_, tokens) = app.signed_in_user().await;
    let token = tokens["access_token"].as_str().unwrap();
    let jwks: Value = app
        .client
        .get(app.url("/.well-known/jwks.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let key = &jwks["keys"][0];

    let (signing_input, signature) = token.rsplit_once('.').unwrap();
    let (header, payload) = signing_input.split_once('.').unwrap();
    let header: Value = serde_json::from_slice(&B64.decode(header).unwrap()).unwrap();
    assert_eq!(header["alg"], "EdDSA");
    assert_eq!(header["kid"], key["kid"]);

    let public_key: [u8; 32] = B64
        .decode(key["x"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let signature: [u8; 64] = B64.decode(signature).unwrap().try_into().unwrap();
    VerifyingKey::from_bytes(&public_key)
        .unwrap()
        .verify_strict(signing_input.as_bytes(), &Signature::from_bytes(&signature))
        .expect("signature must verify with the JWKS key");

    let claims: Value = serde_json::from_slice(&B64.decode(payload).unwrap()).unwrap();
    assert_eq!(claims["iss"], "axum-auth-service");
    assert_eq!(claims["aud"], "axum-auth-service-clients");
    assert!(claims["exp"].as_i64().unwrap() > claims["iat"].as_i64().unwrap());
}
