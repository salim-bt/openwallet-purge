//! Checkpoint / resume for a multi-tenant drain.
//!
//! Progress is written after each tenant completes; an interrupted run picks up from
//! the last checkpoint. In dry-run the checkpoint is never written (nothing was
//! deleted, so there is nothing to resume past). After a successful full run the file
//! is removed.
//!
//! The on-disk shape is plain JSON with stable field names, so a half-finished drain
//! is inspectable — and resumable — without this binary.

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::progress::sanitize_label;

#[derive(Debug, Serialize, Deserialize)]
pub struct Checkpoint {
    #[serde(rename = "completedTenants", default)]
    pub completed_tenants: Vec<String>,
    #[serde(rename = "startedAt")]
    pub started_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,

    #[serde(skip)]
    path: PathBuf,
}

/// Checkpoint path for this invocation.
///
/// When a SINGLE tenant is targeted, the filename is suffixed with it so parallel
/// single-tenant runs in the same directory don't clobber each other. Allowlist and
/// full-enumeration runs cover multiple tenants and share the default name.
///
/// Note the precedence: `TENANT_ALLOWLIST` beats `TENANT_ID` in target selection, so
/// the filename has to follow the same precedence or resume keys off the wrong file.
pub fn path_for(cfg: &Config) -> PathBuf {
    let allowlist_driving = cfg
        .tenant_allowlist
        .as_ref()
        .is_some_and(|a| !a.is_empty());
    match (&cfg.tenant_id, allowlist_driving) {
        (Some(id), false) => PathBuf::from(format!(
            "./purge-checkpoint-{}.json",
            sanitize_label(id)
        )),
        _ => PathBuf::from("./purge-checkpoint.json"),
    }
}

impl Checkpoint {
    pub fn load(cfg: &Config) -> Self {
        let path = path_for(cfg);
        let now = chrono::Utc::now().to_rfc3339();
        match std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str::<Checkpoint>(&s).ok())
        {
            Some(mut cp) => {
                cp.path = path;
                cp
            }
            None => Checkpoint {
                completed_tenants: Vec::new(),
                started_at: now.clone(),
                updated_at: now,
                path,
            },
        }
    }

    pub fn save(&mut self) -> Result<()> {
        self.updated_at = chrono::Utc::now().to_rfc3339();
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(&self.path, json)
            .with_context(|| format!("could not write checkpoint {}", self.path.display()))
    }

    pub fn remove(&self) {
        // Non-fatal — the file may already be absent.
        let _ = std::fs::remove_file(&self.path);
    }

    pub fn contains(&self, tenant: &str) -> bool {
        self.completed_tenants.iter().any(|t| t == tenant)
    }

    pub fn display_path(&self) -> String {
        self.path.display().to_string()
    }
}
