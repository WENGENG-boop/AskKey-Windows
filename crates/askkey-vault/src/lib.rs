//! Local credential storage for Ask Key on Windows.
//!
//! Metadata and values are encrypted with AES-256-GCM under keys derived from
//! one App-owned vault key; each row is authenticated with HMAC-SHA256,
//! including its plaintext permission column. The vault key is protected with
//! DPAPI for the current user. The helper never links this crate.

mod access;
mod bootstrap;
mod crypto;
mod model;
mod storage;

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, OptionalExtension, Row};
use zeroize::Zeroizing;

pub use access::{AccessDecision, AccessRecord};
pub use model::{
    display_name, normalized_name, valid_environment_variable, ComponentInput, ComponentSpec,
    Credential, CredentialUpdate, NewCredential, Permission,
};

use crypto::VaultKeys;
use model::{clean_group, legacy_normalized_name, validate_components, validate_usage, StoredMeta};

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("storage failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("database failed: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("stored data failed authentication")]
    Authentication,
    #[error("the vault key exists but its database is missing")]
    MissingDatabase,
    #[error("the database exists but its vault key is missing")]
    MissingKey,
    #[error("the library uses an unsupported schema")]
    UnsupportedSchema,
    #[error("{0}")]
    Invalid(&'static str),
    #[error("a credential with this name already exists")]
    NameTaken,
    #[error("credential not found")]
    NotFound,
}

pub type Result<T> = std::result::Result<T, VaultError>;

/// Development and production keep separate data and keys.
pub fn default_directory(development: bool) -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    if development {
        base.join("AskKey").join("dev")
    } else {
        base.join("AskKey")
    }
}

pub fn key_namespace(development: bool) -> &'static str {
    if development {
        "com.sudohg.askkey.vault.dev"
    } else {
        "com.sudohg.askkey.vault"
    }
}

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

pub struct Vault {
    connection: Mutex<rusqlite::Connection>,
    keys: VaultKeys,
    directory: PathBuf,
}

struct RawRow {
    id: String,
    name_key: Vec<u8>,
    permission: String,
    meta: Vec<u8>,
    secret: Vec<u8>,
    expires_at: Option<i64>,
    created_at: i64,
    updated_at: i64,
    tag: Vec<u8>,
}

const COLUMNS: &str =
    "id, name_key, permission, meta, secret, expires_at, created_at, updated_at, tag";

impl RawRow {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            name_key: row.get(1)?,
            permission: row.get(2)?,
            meta: row.get(3)?,
            secret: row.get(4)?,
            expires_at: row.get(5)?,
            created_at: row.get(6)?,
            updated_at: row.get(7)?,
            tag: row.get(8)?,
        })
    }

    fn authenticated_fields(&self) -> Vec<Vec<u8>> {
        vec![
            self.id.as_bytes().to_vec(),
            self.name_key.clone(),
            self.permission.as_bytes().to_vec(),
            self.meta.clone(),
            self.secret.clone(),
            self.expires_at
                .map(|value| value.to_be_bytes().to_vec())
                .unwrap_or_default(),
            self.created_at.to_be_bytes().to_vec(),
            self.updated_at.to_be_bytes().to_vec(),
        ]
    }

    fn sign(&mut self, keys: &VaultKeys) {
        let fields = self.authenticated_fields();
        self.tag = keys.record_tag(&fields.iter().map(Vec::as_slice).collect::<Vec<_>>());
    }
}

fn meta_context(id: &str) -> String {
    format!("askkey/credential/{id}/meta")
}

fn secret_context(id: &str) -> String {
    format!("askkey/credential/{id}/secret")
}

impl Vault {
    /// Opens or creates the library in `directory`.
    pub fn open(directory: &Path, key_namespace: &str) -> Result<Self> {
        let opened = bootstrap::open_library(directory, key_namespace)?;
        let vault = Self {
            connection: Mutex::new(opened.connection),
            keys: opened.keys,
            directory: directory.to_path_buf(),
        };
        vault.prune_access_records()?;
        vault.rekey_legacy_names()?;
        Ok(vault)
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    fn connection(&self) -> MutexGuard<'_, rusqlite::Connection> {
        self.connection
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn open_meta(&self, raw: &RawRow) -> Result<StoredMeta> {
        let fields = raw.authenticated_fields();
        self.keys.verify_record(
            &fields.iter().map(Vec::as_slice).collect::<Vec<_>>(),
            &raw.tag,
        )?;
        let meta_bytes = self.keys.open(&raw.meta, &meta_context(&raw.id))?;
        serde_json::from_slice(&meta_bytes).map_err(|_| VaultError::Authentication)
    }

    fn decode(&self, raw: &RawRow) -> Result<Credential> {
        let meta = self.open_meta(raw)?;
        let name_key = self.keys.name_key(&normalized_name(&meta.name));
        if name_key != raw.name_key
            && self.keys.name_key(&legacy_normalized_name(&meta.name)) != raw.name_key
        {
            return Err(VaultError::Authentication);
        }
        Ok(Credential {
            id: raw.id.clone(),
            name: meta.name,
            permission: Permission::parse(&raw.permission)?,
            usage_instructions: meta.usage_instructions,
            group: meta.group,
            components: meta.components,
            expires_at: raw.expires_at,
            created_at: raw.created_at,
            updated_at: raw.updated_at,
            revision: raw.tag.iter().map(|byte| format!("{byte:02x}")).collect(),
        })
    }

    fn raw_rows(&self) -> Result<Vec<RawRow>> {
        let connection = self.connection();
        let mut statement = connection.prepare(&format!("SELECT {COLUMNS} FROM credentials"))?;
        let rows = statement
            .query_map([], RawRow::from_row)?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    /// Moves rows keyed by the first preview's lowercasing to full case
    /// folding. A row whose folded name now collides keeps its old key.
    fn rekey_legacy_names(&self) -> Result<()> {
        for mut raw in self.raw_rows()? {
            let meta = self.open_meta(&raw)?;
            let name_key = self.keys.name_key(&normalized_name(&meta.name));
            if name_key == raw.name_key {
                continue;
            }
            raw.name_key = name_key;
            raw.sign(&self.keys);
            match self.write_row(&raw, false) {
                Ok(()) | Err(VaultError::NameTaken) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn raw(&self, id: &str) -> Result<RawRow> {
        self.connection()
            .query_row(
                &format!("SELECT {COLUMNS} FROM credentials WHERE id = ?1"),
                [id],
                RawRow::from_row,
            )
            .optional()?
            .ok_or(VaultError::NotFound)
    }

    /// Every credential, sorted by name. Fails if any row fails
    /// authentication rather than silently hiding it.
    pub fn list(&self) -> Result<Vec<Credential>> {
        let mut credentials = self
            .raw_rows()?
            .iter()
            .map(|raw| self.decode(raw))
            .collect::<Result<Vec<_>>>()?;
        credentials.sort_by_key(|credential| normalized_name(&credential.name));
        Ok(credentials)
    }

    pub fn get(&self, id: &str) -> Result<Credential> {
        self.decode(&self.raw(id)?)
    }

    /// Looks a credential up by display name (NFC, case-insensitive).
    pub fn find_by_name(&self, name: &str) -> Result<Option<Credential>> {
        let key = self.keys.name_key(&normalized_name(&display_name(name)?));
        let raw = self
            .connection()
            .query_row(
                &format!("SELECT {COLUMNS} FROM credentials WHERE name_key = ?1"),
                [key],
                RawRow::from_row,
            )
            .optional()?;
        raw.map(|raw| self.decode(&raw)).transpose()
    }

    fn seal_row(
        &self,
        id: &str,
        meta: &StoredMeta,
        values: &[Zeroizing<String>],
        permission: Permission,
        expires_at: Option<i64>,
        created_at: i64,
    ) -> Result<RawRow> {
        let meta_json =
            serde_json::to_vec(meta).map_err(|_| VaultError::Invalid("unencodable metadata"))?;
        let plain: Vec<&str> = values.iter().map(|value| value.as_str()).collect();
        let secret_json = Zeroizing::new(
            serde_json::to_vec(&plain).map_err(|_| VaultError::Invalid("unencodable value"))?,
        );
        let mut raw = RawRow {
            id: id.to_owned(),
            name_key: self.keys.name_key(&normalized_name(&meta.name)),
            permission: permission.as_str().to_owned(),
            meta: self.keys.seal(&meta_json, &meta_context(id)),
            secret: self.keys.seal(&secret_json, &secret_context(id)),
            expires_at,
            created_at,
            updated_at: now(),
            tag: Vec::new(),
        };
        raw.sign(&self.keys);
        Ok(raw)
    }

    fn write_row(&self, raw: &RawRow, insert: bool) -> Result<()> {
        let sql = if insert {
            format!(
                "INSERT INTO credentials ({COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"
            )
        } else {
            "UPDATE credentials SET name_key = ?2, permission = ?3, meta = ?4, secret = ?5, expires_at = ?6, \
             created_at = ?7, updated_at = ?8, tag = ?9 WHERE id = ?1"
                .to_owned()
        };
        let result = self.connection().execute(
            &sql,
            params![
                raw.id,
                raw.name_key,
                raw.permission,
                raw.meta,
                raw.secret,
                raw.expires_at,
                raw.created_at,
                raw.updated_at,
                raw.tag
            ],
        );
        match result {
            Err(rusqlite::Error::SqliteFailure(error, _))
                if error.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Err(VaultError::NameTaken)
            }
            Err(error) => Err(error.into()),
            Ok(0) => Err(VaultError::NotFound),
            Ok(_) => Ok(()),
        }
    }

    pub fn create(&self, new: NewCredential) -> Result<Credential> {
        let name = display_name(&new.name)?;
        validate_usage(&new.usage_instructions)?;
        validate_components(&new.components)?;
        let mut values = Vec::new();
        let mut specs = Vec::new();
        for component in new.components {
            let value = component
                .value
                .ok_or(VaultError::Invalid("every component needs a value"))?;
            values.push(Zeroizing::new(value));
            specs.push(ComponentSpec {
                name: component.name.trim().to_owned(),
                environment_variable: component.environment_variable,
            });
        }
        let meta = StoredMeta {
            name,
            usage_instructions: new.usage_instructions,
            group: clean_group(new.group)?,
            components: specs,
        };
        let id = uuid::Uuid::new_v4().to_string();
        let raw = self.seal_row(&id, &meta, &values, new.permission, new.expires_at, now())?;
        self.write_row(&raw, true)?;
        self.get(&id)
    }

    /// Replaces metadata and components. A component given without a value
    /// keeps the stored value of the existing component with the same name.
    pub fn update(&self, id: &str, update: CredentialUpdate) -> Result<Credential> {
        let current = self.get(id)?;
        let current_values = self.values(id)?;
        let name = display_name(&update.name)?;
        validate_usage(&update.usage_instructions)?;
        validate_components(&update.components)?;
        let mut values = Vec::new();
        let mut specs = Vec::new();
        for component in update.components {
            let value = match component.value {
                Some(value) => Zeroizing::new(value),
                None => {
                    let key = normalized_name(component.name.trim());
                    let index = current
                        .components
                        .iter()
                        .position(|existing| normalized_name(&existing.name) == key)
                        .ok_or(VaultError::Invalid("new components need a value"))?;
                    current_values[index].clone()
                }
            };
            values.push(value);
            specs.push(ComponentSpec {
                name: component.name.trim().to_owned(),
                environment_variable: component.environment_variable,
            });
        }
        let meta = StoredMeta {
            name,
            usage_instructions: update.usage_instructions,
            group: clean_group(update.group)?,
            components: specs,
        };
        let raw = self.seal_row(
            id,
            &meta,
            &values,
            current.permission,
            update.expires_at,
            current.created_at,
        )?;
        self.write_row(&raw, false)?;
        self.get(id)
    }

    pub fn set_permission(&self, id: &str, permission: Permission) -> Result<Credential> {
        let current = self.get(id)?;
        let values = self.values(id)?;
        let meta = StoredMeta {
            name: current.name,
            usage_instructions: current.usage_instructions,
            group: current.group,
            components: current.components,
        };
        let raw = self.seal_row(
            id,
            &meta,
            &values,
            permission,
            current.expires_at,
            current.created_at,
        )?;
        self.write_row(&raw, false)?;
        self.get(id)
    }

    pub fn delete(&self, id: &str) -> Result<()> {
        match self
            .connection()
            .execute("DELETE FROM credentials WHERE id = ?1", [id])?
        {
            0 => Err(VaultError::NotFound),
            _ => Ok(()),
        }
    }

    /// Decrypted component values, in component order. Only the App calls
    /// this: for delivery after authorization, or for an authenticated reveal.
    pub fn values(&self, id: &str) -> Result<Vec<Zeroizing<String>>> {
        let raw = self.raw(id)?;
        self.decode(&raw)?;
        let plain = self.keys.open(&raw.secret, &secret_context(id))?;
        let values: Vec<String> =
            serde_json::from_slice(&plain).map_err(|_| VaultError::Authentication)?;
        Ok(values.into_iter().map(Zeroizing::new).collect())
    }

    pub fn setting(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .connection()
            .query_row("SELECT value FROM settings WHERE key = ?1", [key], |row| {
                row.get(0)
            })
            .optional()?)
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        self.connection().execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [key, value],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
