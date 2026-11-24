//! JWT de acesso assinado com Ed25519 (JWS compacto, `alg = EdDSA`).
//!
//! A verificação aceita **um** algoritmo e **uma** chave: o cabeçalho só é lido
//! para conferir que bate com o esperado, nunca para escolher como verificar.
//! Isso fecha, por construção, os ataques clássicos de `alg: none` e de troca
//! de algoritmo. A chave pública é publicada como JWK (RFC 8037) em
//! `/.well-known/jwks.json`, com o `kid` igual ao thumbprint RFC 7638.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, anyhow};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use chrono::{DateTime, Utc};
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::configuration::JwtSettings;

const ALGORITHM: &str = "EdDSA";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum JwtError {
    #[error("token is malformed")]
    Malformed,
    #[error("unsupported algorithm")]
    UnsupportedAlgorithm,
    #[error("unknown signing key")]
    UnknownKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid issuer or audience")]
    InvalidClaims,
    #[error("token expired")]
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claims {
    pub iss: String,
    pub aud: String,
    pub sub: Uuid,
    pub iat: i64,
    pub exp: i64,
    pub jti: Uuid,
}

#[derive(Serialize, Deserialize)]
struct Header {
    alg: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    typ: Option<String>,
    #[serde(default)]
    kid: Option<String>,
}

/// Conjunto de chaves públicas no formato JWKS (RFC 7517).
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// Chave pública Ed25519 como JWK do tipo OKP (RFC 8037).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Jwk {
    #[schema(example = "OKP")]
    pub kty: String,
    #[schema(example = "Ed25519")]
    pub crv: String,
    #[schema(example = "EdDSA")]
    pub alg: String,
    #[serde(rename = "use")]
    #[schema(example = "sig")]
    pub key_use: String,
    pub kid: String,
    /// Chave pública crua (32 bytes) em base64url sem padding.
    pub x: String,
}

pub struct JwtKeys {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    kid: String,
    issuer: String,
    audience: String,
    ttl_seconds: i64,
}

impl JwtKeys {
    pub fn new(signing_key: SigningKey, settings: &JwtSettings) -> Self {
        let verifying_key = signing_key.verifying_key();
        Self {
            kid: thumbprint(&verifying_key),
            signing_key,
            verifying_key,
            issuer: settings.issuer.clone(),
            audience: settings.audience.clone(),
            ttl_seconds: settings.access_token_ttl_seconds,
        }
    }

    /// Carrega a chave do PEM em memória, ou do arquivo, ou (só se permitido) gera uma nova.
    pub fn from_settings(settings: &JwtSettings) -> anyhow::Result<Self> {
        if let Some(pem) = &settings.private_key_pem {
            return Ok(Self::new(parse_pem(pem.expose_secret())?, settings));
        }
        let path = settings
            .private_key_path
            .as_deref()
            .context("set jwt.private_key_pem or jwt.private_key_path")?;

        let signing_key = match std::fs::read_to_string(path) {
            Ok(pem) => parse_pem(&pem)?,
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound && settings.generate_key_if_missing =>
            {
                let key = generate_signing_key()?;
                write_private_key(path, &key)?;
                tracing::warn!(
                    path = %path.display(),
                    "generated a new JWT signing key; never rely on this outside development"
                );
                key
            }
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("cannot read JWT private key at {}", path.display()));
            }
        };
        Ok(Self::new(signing_key, settings))
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn access_token_ttl_seconds(&self) -> i64 {
        self.ttl_seconds
    }

    pub fn issue(&self, user_id: Uuid, now: DateTime<Utc>) -> Result<String, JwtError> {
        let claims = Claims {
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            sub: user_id,
            iat: now.timestamp(),
            exp: now.timestamp() + self.ttl_seconds,
            jti: Uuid::now_v7(),
        };
        let header = Header {
            alg: ALGORITHM.to_owned(),
            typ: Some("JWT".to_owned()),
            kid: Some(self.kid.clone()),
        };
        let header = B64.encode(serde_json::to_vec(&header).map_err(|_| JwtError::Malformed)?);
        let payload = B64.encode(serde_json::to_vec(&claims).map_err(|_| JwtError::Malformed)?);
        let signing_input = format!("{header}.{payload}");
        let signature = self.signing_key.sign(signing_input.as_bytes());
        Ok(format!(
            "{signing_input}.{}",
            B64.encode(signature.to_bytes())
        ))
    }

    pub fn verify(&self, token: &str, now: DateTime<Utc>) -> Result<Claims, JwtError> {
        let mut parts = token.split('.');
        let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(JwtError::Malformed);
        };

        let header: Header = decode_json(header_b64)?;
        if header.alg != ALGORITHM {
            return Err(JwtError::UnsupportedAlgorithm);
        }
        if header.kid.as_deref() != Some(self.kid.as_str()) {
            return Err(JwtError::UnknownKey);
        }

        let signature: [u8; 64] = B64
            .decode(signature_b64)
            .map_err(|_| JwtError::Malformed)?
            .try_into()
            .map_err(|_| JwtError::Malformed)?;
        let signing_input = &token[..header_b64.len() + 1 + payload_b64.len()];
        // verify_strict recusa assinaturas maleáveis e chaves de ordem pequena.
        self.verifying_key
            .verify_strict(signing_input.as_bytes(), &Signature::from_bytes(&signature))
            .map_err(|_| JwtError::InvalidSignature)?;

        let claims: Claims = decode_json(payload_b64)?;
        if claims.iss != self.issuer || claims.aud != self.audience {
            return Err(JwtError::InvalidClaims);
        }
        if now.timestamp() >= claims.exp {
            return Err(JwtError::Expired);
        }
        Ok(claims)
    }

    pub fn jwks(&self) -> Jwks {
        Jwks {
            keys: vec![Jwk {
                kty: "OKP".to_owned(),
                crv: "Ed25519".to_owned(),
                alg: ALGORITHM.to_owned(),
                key_use: "sig".to_owned(),
                kid: self.kid.clone(),
                x: B64.encode(self.verifying_key.as_bytes()),
            }],
        }
    }
}

/// Gera uma chave Ed25519 nova a partir de 32 bytes do gerador do sistema operacional.
pub fn generate_signing_key() -> anyhow::Result<SigningKey> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| anyhow!("OS random generator failed: {e}"))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Serializa a chave em PEM PKCS#8 — o mesmo formato de `openssl genpkey -algorithm ed25519`.
pub fn signing_key_to_pem(key: &SigningKey) -> anyhow::Result<String> {
    key.to_pkcs8_pem(Default::default())
        .map(|pem| pem.to_string())
        .map_err(|e| anyhow!("cannot encode the Ed25519 key as PKCS#8: {e}"))
}

fn parse_pem(pem: &str) -> anyhow::Result<SigningKey> {
    SigningKey::from_pkcs8_pem(pem).map_err(|e| anyhow!("invalid Ed25519 PKCS#8 PEM: {e}"))
}

fn write_private_key(path: &Path, key: &SigningKey) -> anyhow::Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    let mut options = std::fs::OpenOptions::new();
    // create_new: nunca sobrescreve uma chave que já exista.
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    file.write_all(signing_key_to_pem(key)?.as_bytes())?;
    Ok(())
}

/// Thumbprint RFC 7638: SHA-256 dos membros obrigatórios do JWK, em ordem alfabética.
fn thumbprint(key: &VerifyingKey) -> String {
    let canonical = format!(
        r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
        B64.encode(key.as_bytes())
    );
    B64.encode(Sha256::digest(canonical.as_bytes()))
}

fn decode_json<T: for<'de> Deserialize<'de>>(segment: &str) -> Result<T, JwtError> {
    let bytes = B64.decode(segment).map_err(|_| JwtError::Malformed)?;
    serde_json::from_slice(&bytes).map_err(|_| JwtError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn settings() -> JwtSettings {
        JwtSettings {
            issuer: "issuer".into(),
            audience: "audience".into(),
            access_token_ttl_seconds: 900,
            private_key_pem: None,
            private_key_path: None,
            generate_key_if_missing: false,
        }
    }

    fn keys() -> JwtKeys {
        JwtKeys::new(generate_signing_key().unwrap(), &settings())
    }

    fn replace_segment(token: &str, index: usize, value: &str) -> String {
        let mut parts: Vec<&str> = token.split('.').collect();
        parts[index] = value;
        parts.join(".")
    }

    #[test]
    fn rfc8037_example_key_has_the_published_thumbprint() {
        // Chave e thumbprint do Apêndice A da RFC 8037.
        let seed: [u8; 32] = B64
            .decode("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A")
            .unwrap()
            .try_into()
            .unwrap();
        let keys = JwtKeys::new(SigningKey::from_bytes(&seed), &settings());
        assert_eq!(
            keys.jwks().keys[0].x,
            "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        );
        assert_eq!(keys.kid(), "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
    }

    #[test]
    fn issued_token_round_trips() {
        let keys = keys();
        let user = Uuid::now_v7();
        let now = Utc::now();
        let claims = keys.verify(&keys.issue(user, now).unwrap(), now).unwrap();
        assert_eq!(claims.sub, user);
        assert_eq!(claims.exp - claims.iat, 900);
        assert_eq!(
            (claims.iss.as_str(), claims.aud.as_str()),
            ("issuer", "audience")
        );
    }

    #[test]
    fn expired_token_is_rejected() {
        let keys = keys();
        let issued_at = Utc::now() - Duration::seconds(901);
        let token = keys.issue(Uuid::now_v7(), issued_at).unwrap();
        assert_eq!(keys.verify(&token, Utc::now()), Err(JwtError::Expired));
    }

    #[test]
    fn tampered_payload_fails_the_signature() {
        let keys = keys();
        let now = Utc::now();
        let token = keys.issue(Uuid::now_v7(), now).unwrap();
        let mut claims: Claims = decode_json(token.split('.').nth(1).unwrap()).unwrap();
        claims.sub = Uuid::now_v7();
        let forged = replace_segment(&token, 1, &B64.encode(serde_json::to_vec(&claims).unwrap()));
        assert_eq!(keys.verify(&forged, now), Err(JwtError::InvalidSignature));
    }

    #[test]
    fn alg_none_and_other_algorithms_are_rejected() {
        let keys = keys();
        let now = Utc::now();
        let token = keys.issue(Uuid::now_v7(), now).unwrap();
        for alg in ["none", "HS256", "RS256"] {
            let header = format!(r#"{{"alg":"{alg}","kid":"{}"}}"#, keys.kid());
            let forged = replace_segment(&token, 0, &B64.encode(header));
            assert_eq!(
                keys.verify(&forged, now),
                Err(JwtError::UnsupportedAlgorithm)
            );
        }
    }

    #[test]
    fn token_signed_by_another_key_is_rejected() {
        let (ours, theirs) = (keys(), keys());
        let now = Utc::now();
        let token = theirs.issue(Uuid::now_v7(), now).unwrap();
        assert_eq!(ours.verify(&token, now), Err(JwtError::UnknownKey));
    }

    #[test]
    fn wrong_audience_is_rejected() {
        let ours = keys();
        let mut other_settings = settings();
        other_settings.audience = "someone-else".into();
        let pem = signing_key_to_pem(&ours.signing_key).unwrap();
        let other = JwtKeys::new(parse_pem(&pem).unwrap(), &other_settings);
        let now = Utc::now();
        let token = other.issue(Uuid::now_v7(), now).unwrap();
        assert_eq!(ours.verify(&token, now), Err(JwtError::InvalidClaims));
    }

    #[test]
    fn garbage_is_malformed() {
        let keys = keys();
        for token in ["", "a.b", "a.b.c.d", "!!!.???.***"] {
            assert_eq!(
                keys.verify(token, Utc::now()),
                Err(JwtError::Malformed),
                "{token}"
            );
        }
    }
}
