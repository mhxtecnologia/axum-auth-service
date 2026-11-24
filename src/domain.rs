//! Regras de entrada: formato de e-mail e política de senha.

use crate::error::AppError;

pub const PASSWORD_MIN_CHARS: usize = 12;
pub const PASSWORD_MAX_CHARS: usize = 128;

/// Normaliza (trim + minúsculas) e valida um e-mail.
///
/// A validação é estrutural de propósito: a única prova real de que o e-mail
/// existe é uma mensagem de confirmação, que fica fora do escopo deste serviço.
pub fn normalize_email(raw: &str) -> Result<String, AppError> {
    let email = raw.trim().to_lowercase();
    let invalid = || AppError::Validation("email is not a valid address".into());

    if email.len() > 254 || email.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(invalid());
    }
    let (local, domain) = email.split_once('@').ok_or_else(invalid)?;
    let domain_ok = domain.contains('.')
        && !domain.contains('@')
        && !domain.contains("..")
        && domain
            .split('.')
            .all(|label| !label.is_empty() && !label.starts_with('-') && !label.ends_with('-'));
    if local.is_empty() || local.len() > 64 || !domain_ok {
        return Err(invalid());
    }
    Ok(email)
}

/// Política de senha no estilo NIST SP 800-63B: só comprimento, sem regras de composição.
pub fn validate_password(password: &str) -> Result<(), AppError> {
    let chars = password.chars().count();
    if chars < PASSWORD_MIN_CHARS {
        return Err(AppError::Validation(format!(
            "password must have at least {PASSWORD_MIN_CHARS} characters"
        )));
    }
    if chars > PASSWORD_MAX_CHARS {
        return Err(AppError::Validation(format!(
            "password must have at most {PASSWORD_MAX_CHARS} characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_is_trimmed_and_lowercased() {
        assert_eq!(
            normalize_email("  Ada.Lovelace@Example.COM ").unwrap(),
            "ada.lovelace@example.com"
        );
    }

    #[test]
    fn malformed_emails_are_rejected() {
        let too_long = format!("{}@example.com", "a".repeat(65));
        for email in [
            "",
            "plainaddress",
            "@example.com",
            "ada@",
            "ada@localhost",
            "ada@@example.com",
            "ada@exa..mple.com",
            "ada@-example.com",
            "ada lovelace@example.com",
            too_long.as_str(),
        ] {
            assert!(
                normalize_email(email).is_err(),
                "{email:?} should be rejected"
            );
        }
    }

    #[test]
    fn password_length_is_counted_in_characters() {
        assert!(validate_password("short").is_err());
        assert!(validate_password(&"é".repeat(PASSWORD_MIN_CHARS)).is_ok());
        assert!(validate_password(&"x".repeat(PASSWORD_MAX_CHARS + 1)).is_err());
    }
}
