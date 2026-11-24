//! Hash de senha com Argon2id (formato PHC, salt aleatório de 16 bytes).
//!
//! As operações são caras de propósito: quem chama deve rodá-las em
//! `tokio::task::spawn_blocking` para não travar o runtime assíncrono.

use argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
    password_hash::{self, SaltString},
};

use crate::configuration::PasswordSettings;

#[derive(Debug, thiserror::Error)]
#[error("password hashing failed: {0}")]
pub struct PasswordError(String);

pub struct Passwords {
    params: Params,
    /// Hash de uma senha qualquer, verificado quando o e-mail não existe:
    /// o login leva o mesmo tempo com ou sem conta, e não denuncia quem está cadastrado.
    dummy_hash: String,
}

impl Passwords {
    pub fn new(settings: &PasswordSettings) -> Result<Self, PasswordError> {
        let params = Params::new(
            settings.memory_kib,
            settings.iterations,
            settings.parallelism,
            None,
        )
        .map_err(|e| PasswordError(e.to_string()))?;
        let mut passwords = Self {
            params,
            dummy_hash: String::new(),
        };
        passwords.dummy_hash = passwords.hash("timing-equalization-placeholder")?;
        Ok(passwords)
    }

    fn argon2(&self) -> Argon2<'static> {
        Argon2::new(Algorithm::Argon2id, Version::V0x13, self.params.clone())
    }

    pub fn hash(&self, password: &str) -> Result<String, PasswordError> {
        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt).map_err(|e| PasswordError(e.to_string()))?;
        let salt = SaltString::encode_b64(&salt).map_err(|e| PasswordError(e.to_string()))?;
        self.argon2()
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|e| PasswordError(e.to_string()))
    }

    /// `Ok(false)` para senha errada; `Err` só para hash corrompido ou falha interna.
    pub fn verify(&self, password: &str, phc_hash: &str) -> Result<bool, PasswordError> {
        let parsed = PasswordHash::new(phc_hash).map_err(|e| PasswordError(e.to_string()))?;
        match self.argon2().verify_password(password.as_bytes(), &parsed) {
            Ok(()) => Ok(true),
            Err(password_hash::Error::Password) => Ok(false),
            Err(e) => Err(PasswordError(e.to_string())),
        }
    }

    /// Gasta o mesmo trabalho de uma verificação real e descarta o resultado.
    pub fn verify_dummy(&self, password: &str) {
        let _ = self.verify(password, &self.dummy_hash);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_passwords() -> Passwords {
        Passwords::new(&PasswordSettings {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
        })
        .unwrap()
    }

    #[test]
    fn hashes_with_argon2id_in_phc_format() {
        let hash = fast_passwords().hash("a long enough password").unwrap();
        assert!(hash.starts_with("$argon2id$v=19$m=1024,t=1,p=1$"), "{hash}");
    }

    #[test]
    fn verifies_the_right_password_and_rejects_a_wrong_one() {
        let passwords = fast_passwords();
        let hash = passwords.hash("correct horse battery staple").unwrap();
        assert!(
            passwords
                .verify("correct horse battery staple", &hash)
                .unwrap()
        );
        assert!(
            !passwords
                .verify("correct horse battery stapler", &hash)
                .unwrap()
        );
    }

    #[test]
    fn same_password_gets_a_different_salt_each_time() {
        let passwords = fast_passwords();
        assert_ne!(
            passwords.hash("same password twice").unwrap(),
            passwords.hash("same password twice").unwrap()
        );
    }

    #[test]
    fn corrupted_hash_is_an_error_not_a_mismatch() {
        assert!(
            fast_passwords()
                .verify("whatever", "not-a-phc-string")
                .is_err()
        );
    }
}
