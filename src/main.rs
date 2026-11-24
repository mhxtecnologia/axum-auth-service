use anyhow::Context;
use axum_auth_service::configuration::get_configuration;
use axum_auth_service::startup::Application;
use axum_auth_service::telemetry::init_subscriber;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let settings = get_configuration().context("failed to load configuration")?;
    init_subscriber(&settings.telemetry);

    let application = Application::build(settings).await?;
    tracing::info!(port = application.port(), "axum-auth-service is listening");
    application.run_until_stopped().await?;
    Ok(())
}
