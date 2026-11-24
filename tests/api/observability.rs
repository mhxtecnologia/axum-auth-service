use crate::helpers::spawn_app;

#[tokio::test]
async fn every_response_carries_a_request_id() {
    let app = spawn_app().await;

    let response = app
        .client
        .get(app.url("/health/live"))
        .send()
        .await
        .unwrap();

    let id = response.headers()["x-request-id"].to_str().unwrap();
    assert!(uuid::Uuid::parse_str(id).is_ok(), "{id}");
}

#[tokio::test]
async fn a_request_id_sent_by_the_caller_is_propagated() {
    let app = spawn_app().await;

    let response = app
        .client
        .get(app.url("/health/live"))
        .header("x-request-id", "trace-from-the-gateway")
        .send()
        .await
        .unwrap();

    assert_eq!(response.headers()["x-request-id"], "trace-from-the-gateway");
}
