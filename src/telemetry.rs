//! Logs estruturados com `tracing`: JSON em produção, legível no terminal em desenvolvimento.

use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::configuration::{LogFormat, TelemetrySettings};

/// Instala o subscriber global. `RUST_LOG`, quando definido, vence a configuração.
///
/// Chamar duas vezes não derruba o processo: a segunda chamada é ignorada
/// (útil nos testes, que sobem várias instâncias no mesmo binário).
pub fn init_subscriber(settings: &TelemetrySettings) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&settings.log_level));
    let registry = tracing_subscriber::registry().with(filter);

    let result = match settings.log_format {
        LogFormat::Json => registry
            .with(
                fmt::layer()
                    .json()
                    .with_current_span(true)
                    .with_span_list(false),
            )
            .try_init(),
        LogFormat::Pretty => registry.with(fmt::layer()).try_init(),
    };
    // Erro aqui só significa que já havia um subscriber instalado.
    let _ = result;
}
