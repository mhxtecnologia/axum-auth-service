//! Limite de tentativas de login em janela fixa, no Redis.
//!
//! Dois contadores por tentativa: por e-mail (protege a conta de força bruta)
//! e por IP (freia quem testa uma senha em muitas contas). A tentativa é
//! contada **antes** de verificar a senha, então o bloqueio também poupa a CPU
//! do Argon2. Um login certo zera o contador do e-mail; o do IP só expira, para
//! que uma conta válida do atacante não sirva para resetá-lo.

use std::net::IpAddr;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use sha2::{Digest, Sha256};

use crate::configuration::RateLimitSettings;

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Allowed,
    Limited { retry_after_seconds: u64 },
}

#[derive(Clone)]
pub struct LoginRateLimiter {
    redis: ConnectionManager,
    prefix: String,
    max_per_email: u64,
    max_per_ip: u64,
    window_seconds: u64,
}

impl LoginRateLimiter {
    pub fn new(redis: ConnectionManager, prefix: &str, settings: &RateLimitSettings) -> Self {
        Self {
            redis,
            prefix: prefix.to_owned(),
            max_per_email: settings.login_max_attempts_per_email.into(),
            max_per_ip: settings.login_max_attempts_per_ip.into(),
            window_seconds: settings.window_seconds,
        }
    }

    /// Registra uma tentativa e diz se ela pode seguir.
    pub async fn hit(&self, email: &str, ip: IpAddr) -> redis::RedisResult<Decision> {
        let email_key = self.email_key(email);
        let ip_key = self.ip_key(ip);
        let mut conn = self.redis.clone();

        // MULTI/EXEC: incremento e expiração atômicos. `EXPIRE ... NX` (Redis 7+)
        // só define o prazo na primeira tentativa, então a janela não se estende.
        let (email_count, email_ttl, ip_count, ip_ttl): (u64, i64, u64, i64) = redis::pipe()
            .atomic()
            .incr(&email_key, 1)
            .cmd("EXPIRE")
            .arg(&email_key)
            .arg(self.window_seconds)
            .arg("NX")
            .ignore()
            .ttl(&email_key)
            .incr(&ip_key, 1)
            .cmd("EXPIRE")
            .arg(&ip_key)
            .arg(self.window_seconds)
            .arg("NX")
            .ignore()
            .ttl(&ip_key)
            .query_async(&mut conn)
            .await?;

        let retry_after = |ttl: i64| u64::try_from(ttl).unwrap_or(self.window_seconds).max(1);
        if email_count > self.max_per_email {
            return Ok(Decision::Limited {
                retry_after_seconds: retry_after(email_ttl),
            });
        }
        if ip_count > self.max_per_ip {
            return Ok(Decision::Limited {
                retry_after_seconds: retry_after(ip_ttl),
            });
        }
        Ok(Decision::Allowed)
    }

    /// Chamado após um login bem-sucedido.
    pub async fn reset_email(&self, email: &str) -> redis::RedisResult<()> {
        let mut conn = self.redis.clone();
        let _: i64 = conn.del(self.email_key(email)).await?;
        Ok(())
    }

    fn email_key(&self, email: &str) -> String {
        // O e-mail entra como hash: a chave do Redis não guarda dado pessoal.
        let digest = B64.encode(Sha256::digest(email.as_bytes()));
        format!("{}login:email:{digest}", self.prefix)
    }

    fn ip_key(&self, ip: IpAddr) -> String {
        format!("{}login:ip:{}", self.prefix, ip_bucket(ip))
    }
}

/// IPv4 conta por endereço; IPv6 por prefixo /64, porque um único cliente
/// costuma receber o /64 inteiro e trocaria de endereço a cada tentativa.
pub fn ip_bucket(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_addresses_share_a_bucket_per_64_prefix() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:bbbb::2".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(ip_bucket(a), "2001:db8:1:2::/64");
        assert_eq!(ip_bucket(a), ip_bucket(b));
        assert_ne!(ip_bucket(a), ip_bucket(c));
    }

    #[test]
    fn ipv4_mapped_ipv6_counts_as_the_ipv4_address() {
        let mapped: IpAddr = "::ffff:203.0.113.7".parse().unwrap();
        assert_eq!(ip_bucket(mapped), "203.0.113.7");
    }
}
