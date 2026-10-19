use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

use crate::VaultError;

pub const MAX_NAME_CHARS: usize = 128;
pub const MAX_USAGE_BYTES: usize = 4 * 1024;
pub const MAX_VALUE_BYTES: usize = 16 * 1024;
pub const MAX_COMPONENTS: usize = 64;

/// The one agent permission each credential has. Ask is the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    Allow,
    #[default]
    Ask,
    Hidden,
}

impl Permission {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Ask => "ask",
            Self::Hidden => "hidden",
        }
    }

    pub fn parse(value: &str) -> Result<Self, VaultError> {
        match value {
            "allow" => Ok(Self::Allow),
            "ask" => Ok(Self::Ask),
            "hidden" => Ok(Self::Hidden),
            _ => Err(VaultError::Authentication),
        }
    }
}

/// One named part of a credential and how it is delivered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComponentSpec {
    pub name: String,
    /// `None` means the component is never injected.
    pub environment_variable: Option<String>,
}

/// Encrypted metadata stored with each credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StoredMeta {
    pub name: String,
    pub usage_instructions: String,
    pub group: Option<String>,
    pub components: Vec<ComponentSpec>,
}

/// A credential without its values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credential {
    pub id: String,
    pub name: String,
    pub permission: Permission,
    pub usage_instructions: String,
    pub group: Option<String>,
    pub components: Vec<ComponentSpec>,
    /// Unix seconds.
    pub expires_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
    /// Changes on every write to the credential, including its permission.
    #[serde(skip)]
    pub revision: String,
}

impl Credential {
    pub fn is_expired(&self, now: i64) -> bool {
        self.expires_at.is_some_and(|expiry| expiry <= now)
    }
}

/// Input for a new credential. Values are zeroized after use by the caller.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewCredential {
    pub name: String,
    #[serde(default)]
    pub permission: Permission,
    #[serde(default)]
    pub usage_instructions: String,
    #[serde(default)]
    pub group: Option<String>,
    pub components: Vec<ComponentInput>,
    #[serde(default)]
    pub expires_at: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComponentInput {
    pub name: String,
    pub environment_variable: Option<String>,
    /// `None` on update keeps the stored value of the component with the same
    /// name. Required on creation.
    pub value: Option<String>,
}

/// Replacement metadata and components for an existing credential.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialUpdate {
    pub name: String,
    #[serde(default)]
    pub usage_instructions: String,
    #[serde(default)]
    pub group: Option<String>,
    pub components: Vec<ComponentInput>,
    #[serde(default)]
    pub expires_at: Option<i64>,
}

/// Trimmed display name, in NFC.
pub fn display_name(raw: &str) -> Result<String, VaultError> {
    let name: String = raw.trim().nfc().collect();
    if name.is_empty()
        || name.chars().count() > MAX_NAME_CHARS
        || name.chars().any(char::is_control)
    {
        return Err(VaultError::Invalid("name must be 1-128 visible characters"));
    }
    Ok(name)
}

/// Key used for uniqueness: NFC plus full case folding, so `Straße`,
/// `STRASSE` and `strasse` are one name. Lowercasing, uppercasing and
/// lowercasing again reaches the same equivalence classes as Unicode full
/// case folding without another dependency.
pub fn normalized_name(display: &str) -> String {
    display
        .nfc()
        .flat_map(char::to_lowercase)
        .flat_map(char::to_uppercase)
        .flat_map(char::to_lowercase)
        .nfc()
        .collect()
}

/// The key the first preview release used, which only lowercased. Rows
/// written by it are re-keyed when the library opens.
pub(crate) fn legacy_normalized_name(display: &str) -> String {
    display.nfc().flat_map(char::to_lowercase).nfc().collect()
}

pub fn valid_environment_variable(name: &str) -> bool {
    let mut characters = name.chars();
    matches!(characters.next(), Some(c) if c == '_' || c.is_ascii_alphabetic())
        && characters.all(|c| c == '_' || c.is_ascii_alphanumeric())
        && name.len() <= 128
}

pub(crate) fn validate_components(components: &[ComponentInput]) -> Result<(), VaultError> {
    if components.is_empty() || components.len() > MAX_COMPONENTS {
        return Err(VaultError::Invalid("a credential needs 1-64 components"));
    }
    let mut names = Vec::new();
    let mut variables = Vec::new();
    for component in components {
        let name = normalized_name(component.name.trim());
        if name.is_empty() || component.name.len() > 128 {
            return Err(VaultError::Invalid(
                "component names must be 1-128 characters",
            ));
        }
        if names.contains(&name) {
            return Err(VaultError::Invalid("component names must be unique"));
        }
        names.push(name);
        if let Some(variable) = &component.environment_variable {
            if !valid_environment_variable(variable) {
                return Err(VaultError::Invalid(
                    "environment variable names use letters, digits and _",
                ));
            }
            // Windows variable names are case-insensitive.
            let key = variable.to_ascii_uppercase();
            if variables.contains(&key) {
                return Err(VaultError::Invalid("environment variables must be unique"));
            }
            variables.push(key);
        }
        if component
            .value
            .as_ref()
            .is_some_and(|value| value.len() > MAX_VALUE_BYTES || value.contains('\0'))
        {
            return Err(VaultError::Invalid(
                "values must be at most 16 KiB without NUL characters",
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_usage(usage: &str) -> Result<(), VaultError> {
    if usage.len() > MAX_USAGE_BYTES {
        return Err(VaultError::Invalid(
            "usage instructions are limited to 4 KiB",
        ));
    }
    Ok(())
}

pub(crate) fn clean_group(group: Option<String>) -> Result<Option<String>, VaultError> {
    match group.as_deref().map(str::trim) {
        None | Some("") => Ok(None),
        Some(name) => display_name(name).map(Some),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_fold_case_and_normalize() {
        assert_eq!(normalized_name("GitHub"), normalized_name("github"));
        // "é" precomposed and decomposed.
        assert_eq!(normalized_name("caf\u{e9}"), normalized_name("cafe\u{301}"));
        assert_eq!(normalized_name("Stra\u{df}e"), normalized_name("STRASSE"));
        assert_eq!(normalized_name("STRA\u{1e9e}E"), normalized_name("strasse"));
        assert_eq!(normalized_name("\u{fb01}le"), normalized_name("FILE"));
        assert!(display_name("   ").is_err());
        assert_eq!(display_name("  NAS  ").unwrap(), "NAS");
    }

    #[test]
    fn environment_variables_are_validated_case_insensitively() {
        let component = |name: &str, variable: &str| ComponentInput {
            name: name.into(),
            environment_variable: Some(variable.into()),
            value: Some("synthetic".into()),
        };
        assert!(validate_components(&[component("a", "TOKEN"), component("b", "token")]).is_err());
        assert!(validate_components(&[component("a", "1BAD")]).is_err());
        assert!(validate_components(&[component("a", "GOOD_1")]).is_ok());
    }
}
