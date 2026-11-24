# syntax=docker/dockerfile:1.7

# Estágio de build: compila em release com cache do registry e do target
# (cache mounts do BuildKit), sem levar nada disso para a imagem final.
FROM rust:1.98-slim-trixie AS builder
WORKDIR /app
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked \
    && cp target/release/axum-auth-service /usr/local/bin/axum-auth-service \
    && mkdir -p /keys

# Imagem final: distroless (sem shell nem gerenciador de pacotes), usuário sem root.
FROM gcr.io/distroless/cc-debian13:nonroot
WORKDIR /app
COPY --from=builder /usr/local/bin/axum-auth-service /usr/local/bin/axum-auth-service
COPY configuration ./configuration
# Pasta da chave JWT com dono nonroot: um volume novo montado aqui herda a permissão.
COPY --from=builder --chown=nonroot:nonroot /keys /var/lib/auth/keys
ENV APP_ENVIRONMENT=production
EXPOSE 8080
USER nonroot
ENTRYPOINT ["/usr/local/bin/axum-auth-service"]
