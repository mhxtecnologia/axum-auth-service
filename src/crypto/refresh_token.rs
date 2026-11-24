//! Refresh token opaco: 256 bits aleatórios, entregues ao cliente uma única vez.
//!
//! O banco guarda só o SHA-256 do token. Um hash lento (Argon2) seria
//! desperdício aqui: com 256 bits de entropia não há dicionário a atacar, e o
//! SHA-256 permite buscar o token por índice único em tempo constante.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use sha2::{Digest, Sha256};

pub struct RefreshToken {
    /// Valor devolvido ao cliente; nunca é gravado nem logado.
    pub plaintext: String,
    pub hash: Vec<u8>,
}

pub fn generate() -> Result<RefreshToken, getrandom::Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;
    let plaintext = B64.encode(bytes);
    Ok(RefreshToken {
        hash: hash(&plaintext),
        plaintext,
    })
}

pub fn hash(plaintext: &str) -> Vec<u8> {
    Sha256::digest(plaintext.as_bytes()).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_43_url_safe_chars_and_unique() {
        let (a, b) = (generate().unwrap(), generate().unwrap());
        assert_eq!(a.plaintext.len(), 43);
        assert!(
            a.plaintext
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
        assert_ne!(a.plaintext, b.plaintext);
    }

    #[test]
    fn stored_hash_matches_the_presented_token() {
        let token = generate().unwrap();
        assert_eq!(hash(&token.plaintext), token.hash);
        assert_eq!(token.hash.len(), 32);
    }
}
