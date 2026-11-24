use crate::helpers::{PASSWORD, error_code, spawn_app_with, unique_email};

#[tokio::test]
async fn too_many_failures_lock_the_email_even_for_the_right_password() {
    let app = spawn_app_with(|s| s.rate_limit.login_max_attempts_per_email = 3).await;
    let email = unique_email();
    app.register(&email, PASSWORD).await;

    for _ in 0..3 {
        assert_eq!(
            app.login(&email, "a wrong long password").await.status(),
            401
        );
    }
    let locked = app.login(&email, PASSWORD).await;

    assert_eq!(locked.status(), 429);
    let retry_after: u64 = locked.headers()["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=900).contains(&retry_after), "{retry_after}");
    assert_eq!(error_code(locked).await, "too_many_requests");
}

#[tokio::test]
async fn successful_login_resets_the_email_counter() {
    let app = spawn_app_with(|s| s.rate_limit.login_max_attempts_per_email = 3).await;
    let email = unique_email();
    app.register(&email, PASSWORD).await;

    for _ in 0..2 {
        app.login(&email, "a wrong long password").await;
    }
    assert_eq!(app.login(&email, PASSWORD).await.status(), 200);
    for _ in 0..2 {
        assert_eq!(
            app.login(&email, "a wrong long password").await.status(),
            401
        );
    }
    assert_eq!(app.login(&email, PASSWORD).await.status(), 200);
}

#[tokio::test]
async fn one_ip_spraying_many_accounts_is_limited() {
    let app = spawn_app_with(|s| s.rate_limit.login_max_attempts_per_ip = 3).await;

    for _ in 0..3 {
        assert_eq!(app.login(&unique_email(), PASSWORD).await.status(), 401);
    }

    assert_eq!(app.login(&unique_email(), PASSWORD).await.status(), 429);
}

#[tokio::test]
async fn forwarded_for_header_is_ignored_unless_a_proxy_is_trusted() {
    let app = spawn_app_with(|s| s.rate_limit.login_max_attempts_per_ip = 2).await;
    let attempt = |ip: &'static str| {
        app.client
            .post(app.url("/auth/login"))
            .header("x-forwarded-for", ip)
            .json(&serde_json::json!({ "email": unique_email(), "password": PASSWORD }))
            .send()
    };

    // Trocar o cabeçalho a cada tentativa não engana o limite por IP.
    assert_eq!(attempt("203.0.113.1").await.unwrap().status(), 401);
    assert_eq!(attempt("203.0.113.2").await.unwrap().status(), 401);
    assert_eq!(attempt("203.0.113.3").await.unwrap().status(), 429);
}

#[tokio::test]
async fn trusted_proxy_header_separates_clients() {
    let app = spawn_app_with(|s| {
        s.rate_limit.login_max_attempts_per_ip = 1;
        s.rate_limit.trust_x_forwarded_for = true;
    })
    .await;
    let attempt = |chain: &'static str| {
        app.client
            .post(app.url("/auth/login"))
            .header("x-forwarded-for", chain)
            .json(&serde_json::json!({ "email": unique_email(), "password": PASSWORD }))
            .send()
    };

    // Vale o último IP da lista, o que o proxy acrescentou.
    assert_eq!(
        attempt("198.51.100.9, 203.0.113.1").await.unwrap().status(),
        401
    );
    assert_eq!(
        attempt("198.51.100.9, 203.0.113.2").await.unwrap().status(),
        401
    );
    assert_eq!(
        attempt("198.51.100.9, 203.0.113.1").await.unwrap().status(),
        429
    );
}
