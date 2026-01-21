//! Input validation utilities for authentication methods.

use crate::errors::{AuthMethodsError, Result};

/// Validate email address format.
///
/// Checks basic email format requirements:
/// - Contains exactly one @ symbol
/// - Has non-empty local and domain parts
/// - Domain has at least one dot
/// - Length is within RFC 5321 limits (max 254 characters)
///
/// # Arguments
///
/// * `email` - The email address to validate
///
/// # Returns
///
/// `Ok(())` if the email is valid, or an error describing the validation failure
pub fn validate_email(email: &str) -> Result<()> {
    // Check length (RFC 5321 limit)
    if email.len() > 254 {
        return Err(AuthMethodsError::Other(
            "Email address too long (max 254 characters)".to_string(),
        ));
    }

    if email.is_empty() {
        return Err(AuthMethodsError::Other(
            "Email address cannot be empty".to_string(),
        ));
    }

    // Split on @ and validate parts
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return Err(AuthMethodsError::Other(
            "Invalid email format: must contain exactly one @ symbol".to_string(),
        ));
    }

    let local = parts[0];
    let domain = parts[1];

    // Validate local part (before @)
    if local.is_empty() || local.len() > 64 {
        return Err(AuthMethodsError::Other(
            "Invalid email: local part must be 1-64 characters".to_string(),
        ));
    }

    // Validate domain part (after @)
    if domain.is_empty() || domain.len() > 253 {
        return Err(AuthMethodsError::Other(
            "Invalid email: domain must be 1-253 characters".to_string(),
        ));
    }

    // Domain must contain at least one dot
    if !domain.contains('.') {
        return Err(AuthMethodsError::Other(
            "Invalid email: domain must contain at least one dot".to_string(),
        ));
    }

    // Basic character validation
    if !local
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' || c == '+')
    {
        return Err(AuthMethodsError::Other(
            "Invalid email: local part contains invalid characters".to_string(),
        ));
    }

    if !domain
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(AuthMethodsError::Other(
            "Invalid email: domain contains invalid characters".to_string(),
        ));
    }

    Ok(())
}

/// Validate password strength.
///
/// Requirements:
/// - Minimum 12 characters
/// - Maximum 128 characters
/// - At least one uppercase letter
/// - At least one lowercase letter
/// - At least one digit
/// - At least one special character
///
/// # Arguments
///
/// * `password` - The password to validate
///
/// # Returns
///
/// `Ok(())` if the password meets strength requirements, or an error describing the failure
pub fn validate_password(password: &str) -> Result<()> {
    if password.len() < 12 {
        return Err(AuthMethodsError::Other(
            "Password must be at least 12 characters long".to_string(),
        ));
    }

    if password.len() > 128 {
        return Err(AuthMethodsError::Other(
            "Password must be at most 128 characters long".to_string(),
        ));
    }

    if !password.chars().any(|c| c.is_uppercase()) {
        return Err(AuthMethodsError::Other(
            "Password must contain at least one uppercase letter".to_string(),
        ));
    }

    if !password.chars().any(|c| c.is_lowercase()) {
        return Err(AuthMethodsError::Other(
            "Password must contain at least one lowercase letter".to_string(),
        ));
    }

    if !password.chars().any(|c| c.is_ascii_digit()) {
        return Err(AuthMethodsError::Other(
            "Password must contain at least one digit".to_string(),
        ));
    }

    if !password.chars().any(|c| !c.is_alphanumeric()) {
        return Err(AuthMethodsError::Other(
            "Password must contain at least one special character".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_email_valid() {
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("user+tag@subdomain.example.co.uk").is_ok());
        assert!(validate_email("user_name@example-domain.com").is_ok());
    }

    #[test]
    fn test_validate_email_invalid() {
        assert!(validate_email("").is_err());
        assert!(validate_email("no-at-sign").is_err());
        assert!(validate_email("@example.com").is_err());
        assert!(validate_email("user@").is_err());
        assert!(validate_email("user@@example.com").is_err());
        assert!(validate_email("user@no-dot").is_err());
        assert!(validate_email(&"a".repeat(255)).is_err()); // Too long
    }

    #[test]
    fn test_validate_password_valid() {
        assert!(validate_password("ValidPass123!").is_ok());
        assert!(validate_password("Str0ng&P@ssw0rd").is_ok());
        assert!(validate_password("12345Abcdef!").is_ok());
    }

    #[test]
    fn test_validate_password_invalid() {
        assert!(validate_password("short1!A").is_err()); // Too short
        assert!(validate_password("nouppercaseordigits!").is_err()); // No uppercase or digit
        assert!(validate_password("NOLOWERCASE123!").is_err()); // No lowercase
        assert!(validate_password("NoDigitsHere!").is_err()); // No digits
        assert!(validate_password("NoSpecialChar123A").is_err()); // No special char
        assert!(validate_password(&"a".repeat(129)).is_err()); // Too long
    }
}
