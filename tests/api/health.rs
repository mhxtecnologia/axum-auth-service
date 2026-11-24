use serde_json::Value;

use crate::helpers::spawn_app;

#[tokio::test]
async fn liveness_is_ok() {
    let app = spawn_app().await;
    let response = app
        .client
        .get(app.url("/health/live"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn readiness_checks_postgres_and_redis() {
    let app = spawn_app().await;
    let response = app
        .client
        .get(app.url("/health/ready"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["database"], "ok");
    assert_eq!(body["redis"], "ok");
}

#[tokio::test]
async fn openapi_document_lists_every_endpoint() {
    let app = spawn_app().await;
    let response = app
        .client
        .get(app.url("/api-docs/openapi.json"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let spec: Value = response.json().await.unwrap();
    for path in [
        "/auth/register",
        "/auth/login",
        "/auth/refresh",
        "/auth/logout",
        "/users/me",
        "/.well-known/jwks.json",
        "/health/live",
        "/health/ready",
    ] {
        assert!(
            spec["paths"].get(path).is_some(),
            "{path} missing from OpenAPI"
        );
    }
    assert_eq!(
        spec["components"]["securitySchemes"]["bearer"]["scheme"],
        "bearer"
    );
}
