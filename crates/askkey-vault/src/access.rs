use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::{now, Result, Vault, VaultError};

/// Access records are kept for 90 days.
const RETENTION_SECONDS: i64 = 90 * 24 * 60 * 60;
const CONTEXT: &str = "askkey/access-record";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessDecision {
    Allowed,
    Approved,
    Denied,
    Cancelled,
    Expired,
    Unavailable,
    Failed,
}

/// One agent access attempt. Stores the executable's file name only, never
/// arguments or the working directory, which can contain agent-typed data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessRecord {
    #[serde(default)]
    pub at: i64,
    pub credential_names: Vec<String>,
    pub executable: String,
    pub caller_name: Option<String>,
    pub decision: AccessDecision,
}

impl Vault {
    /// Also drops records past the retention window, because the App can stay
    /// running far longer than that.
    pub fn record_access(&self, mut record: AccessRecord) -> Result<()> {
        record.at = now();
        let encoded =
            serde_json::to_vec(&record).map_err(|_| VaultError::Invalid("unencodable record"))?;
        let sealed = self.keys.seal(&encoded, CONTEXT);
        self.connection().execute(
            "INSERT INTO access_records (at, record) VALUES (?1, ?2)",
            params![record.at, sealed],
        )?;
        self.prune_access_records()
    }

    /// Most recent records first.
    pub fn access_records(&self, limit: usize) -> Result<Vec<AccessRecord>> {
        self.prune_access_records()?;
        let sealed: Vec<Vec<u8>> = {
            let connection = self.connection();
            let mut statement = connection
                .prepare("SELECT record FROM access_records ORDER BY id DESC LIMIT ?1")?;
            let rows = statement
                .query_map([limit as i64], |row| row.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            rows
        };
        sealed
            .iter()
            .map(|blob| {
                let plain = self.keys.open(blob, CONTEXT)?;
                serde_json::from_slice(&plain).map_err(|_| VaultError::Authentication)
            })
            .collect()
    }

    pub(crate) fn prune_access_records(&self) -> Result<()> {
        self.connection().execute(
            "DELETE FROM access_records WHERE at < ?1",
            [now() - RETENTION_SECONDS],
        )?;
        Ok(())
    }
}
