//! CSV audit trail — one row per purged target, written as the run progresses.
//!
//! A nightly destructive job needs a record of what it did that outlives the console
//! log. Each row carries when the purge ran, the parameters it ran with, and how many
//! records of each category it removed, so "what did we delete from RSEB on the 22nd,
//! and at what TTL?" is answerable from one file.
//!
//! Rows are appended and flushed ONE AT A TIME, as each target finishes, not buffered
//! until the end. A drain across 29 tenants that dies on tenant 20 still leaves 19
//! durable rows plus a `failed` row for the one that broke. That is also why a tenant
//! that errors gets a row rather than a gap — a gap is indistinguishable from "never
//! attempted".
//!
//! Audit failures never fail a purge. If the file cannot be written the run continues
//! and warns; losing the log is bad, aborting a half-finished drain over it is worse.

use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use chrono::{DateTime, Utc};

use crate::cascade::PurgeStats;
use crate::config::{Config, PurgeMode};

/// Column order. `AuditRow::fields` must produce exactly these, in this order — there
/// is a test that checks the two stay in step.
const HEADER: &[&str] = &[
    // when
    "started_at",
    "finished_at",
    "duration_s",
    // what ran
    "command",
    "status",
    "mode",
    "purge_mode",
    "target",
    "wallet_id",
    // parameters it ran with
    "ttl_days",
    "stale_incomplete_ttl_days",
    "purge_stale_incomplete",
    "throttle_ms",
    "heartbeat_every",
    "bulk_purge_batch_size",
    "orphan_scan_batch_size",
    "orphan_delete_batch_size",
    "db_max_connections",
    "server_side_delete",
    // what it removed
    "credentials_parents",
    "credentials_children",
    "proofs_parents",
    "proofs_children",
    "oob_records",
    "orphans_deleted",
    "basic_messages",
    "question_answers",
    "total_records",
    // why, if it went wrong
    "error",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    Failed,
    /// Target was named but not present (e.g. a tenant id with no Askar profile).
    Skipped,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Status::Ok => "ok",
            Status::Failed => "failed",
            Status::Skipped => "skipped",
        })
    }
}

/// Per-category totals for one target.
#[derive(Debug, Default, Clone, Copy)]
pub struct Counts {
    pub credentials_parents: u64,
    pub credentials_children: u64,
    pub proofs_parents: u64,
    pub proofs_children: u64,
    pub oob: u64,
    pub orphans: u64,
    pub basic_messages: u64,
    pub question_answers: u64,
}

impl Counts {
    /// Every row actually removed, parents and cascaded children alike. This is the
    /// number that should match the drop in the wallet's row count, which is why the
    /// dry-run census counts children too.
    pub fn total(&self) -> u64 {
        self.credentials_parents
            + self.credentials_children
            + self.proofs_parents
            + self.proofs_children
            + self.oob
            + self.orphans
            + self.basic_messages
            + self.question_answers
    }

    pub fn with_credentials(mut self, s: PurgeStats) -> Self {
        self.credentials_parents = s.parents;
        self.credentials_children = s.children;
        self
    }

    pub fn with_proofs(mut self, s: PurgeStats) -> Self {
        self.proofs_parents = s.parents;
        self.proofs_children = s.children;
        self
    }

    pub fn with_oob(mut self, s: PurgeStats) -> Self {
        self.oob = s.parents;
        self
    }

    pub fn with_orphans(mut self, s: PurgeStats) -> Self {
        self.orphans = s.parents;
        self
    }

    pub fn with_basic_messages(mut self, s: PurgeStats) -> Self {
        self.basic_messages = s.parents;
        self
    }

    pub fn with_question_answers(mut self, s: PurgeStats) -> Self {
        self.question_answers = s.parents;
        self
    }

}

/// One finished target.
pub struct AuditRow {
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub command: String,
    pub status: Status,
    pub target: String,
    pub counts: Counts,
    pub error: Option<String>,
}

impl AuditRow {
    pub fn new(command: &str, target: &str, started_at: DateTime<Utc>) -> Self {
        Self {
            started_at,
            finished_at: Utc::now(),
            command: command.to_string(),
            status: Status::Ok,
            target: target.to_string(),
            counts: Counts::default(),
            error: None,
        }
    }

    pub fn failed(mut self, error: impl fmt::Display) -> Self {
        self.status = Status::Failed;
        self.error = Some(error.to_string());
        self
    }

    pub fn skipped(mut self, reason: impl fmt::Display) -> Self {
        self.status = Status::Skipped;
        self.error = Some(reason.to_string());
        self
    }

    pub fn counts(mut self, counts: Counts) -> Self {
        self.counts = counts;
        self
    }
}

/// Snapshot of the parameters a run used, repeated on every row.
///
/// Denormalised on purpose: a row has to be interpretable on its own, months later,
/// without cross-referencing a separate run table or the shell history.
struct Params {
    mode: &'static str,
    purge_mode: &'static str,
    wallet_id: String,
    ttl_days: String,
    stale_ttl_days: String,
    purge_stale_incomplete: String,
    throttle_ms: String,
    heartbeat_every: String,
    bulk_purge_batch_size: String,
    orphan_scan_batch_size: String,
    orphan_delete_batch_size: String,
    db_max_connections: String,
    server_side_delete: String,
}

pub struct AuditLog {
    path: Option<PathBuf>,
    params: Params,
}

impl AuditLog {
    /// `enabled = false` (the `--no-audit` flag) turns this into a no-op sink.
    pub fn new(cfg: &Config, enabled: bool, server_side_delete: bool) -> Self {
        Self {
            path: if enabled {
                Some(cfg.audit_csv.clone())
            } else {
                None
            },
            params: Params {
                mode: if cfg.dry_run { "dry-run" } else { "live" },
                purge_mode: match cfg.purge_mode {
                    PurgeMode::Dedicated => "dedicated",
                    PurgeMode::MultiTenant => "multi-tenant",
                },
                wallet_id: cfg.wallet_id.clone(),
                ttl_days: cfg.ttl_days.to_string(),
                // Only meaningful when the stale pass is actually on; an empty cell
                // beats a misleading "90" on a row where nothing stale was touched.
                stale_ttl_days: if cfg.purge_stale_incomplete {
                    cfg.stale_incomplete_ttl_days.to_string()
                } else {
                    String::new()
                },
                purge_stale_incomplete: cfg.purge_stale_incomplete.to_string(),
                throttle_ms: cfg.throttle_ms.to_string(),
                heartbeat_every: cfg.heartbeat_every.to_string(),
                bulk_purge_batch_size: cfg.bulk_purge_batch_size.to_string(),
                orphan_scan_batch_size: cfg.orphan_scan_batch_size.to_string(),
                orphan_delete_batch_size: cfg.orphan_delete_batch_size.to_string(),
                db_max_connections: cfg.db_max_connections.to_string(),
                server_side_delete: server_side_delete.to_string(),
            },
        }
    }

    fn fields(&self, row: &AuditRow) -> Vec<String> {
        let duration = (row.finished_at - row.started_at).num_seconds().max(0);
        let c = &row.counts;
        let p = &self.params;
        vec![
            row.started_at.to_rfc3339(),
            row.finished_at.to_rfc3339(),
            duration.to_string(),
            row.command.clone(),
            row.status.to_string(),
            p.mode.to_string(),
            p.purge_mode.to_string(),
            row.target.clone(),
            p.wallet_id.clone(),
            p.ttl_days.clone(),
            p.stale_ttl_days.clone(),
            p.purge_stale_incomplete.clone(),
            p.throttle_ms.clone(),
            p.heartbeat_every.clone(),
            p.bulk_purge_batch_size.clone(),
            p.orphan_scan_batch_size.clone(),
            p.orphan_delete_batch_size.clone(),
            p.db_max_connections.clone(),
            p.server_side_delete.clone(),
            c.credentials_parents.to_string(),
            c.credentials_children.to_string(),
            c.proofs_parents.to_string(),
            c.proofs_children.to_string(),
            c.oob.to_string(),
            c.orphans.to_string(),
            c.basic_messages.to_string(),
            c.question_answers.to_string(),
            c.total().to_string(),
            row.error.clone().unwrap_or_default(),
        ]
    }

    /// Append one row and flush it. Never returns an error — a failure here warns and
    /// the purge carries on.
    pub fn record(&self, row: &AuditRow) {
        let Some(path) = &self.path else { return };
        if let Err(e) = self.try_record(path, row) {
            eprintln!("  \u{26a0}\u{fe0f}  could not write audit row to {}: {e}", path.display());
        }
    }

    fn try_record(&self, path: &PathBuf, row: &AuditRow) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        let is_new = !path.exists() || std::fs::metadata(path).map(|m| m.len() == 0).unwrap_or(true);

        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        if is_new {
            writeln!(file, "{}", HEADER.join(","))?;
        }
        let line: Vec<String> = self.fields(row).iter().map(|f| escape(f)).collect();
        writeln!(file, "{}", line.join(","))?;
        // Flush per row so a killed run keeps everything written up to that point.
        file.flush()
    }

    pub fn path_display(&self) -> Option<String> {
        self.path.as_ref().map(|p| p.display().to_string())
    }
}

/// RFC 4180 field escaping: quote when the field holds a comma, quote, CR or LF, and
/// double any embedded quotes. Error messages routinely contain commas, so this is
/// load-bearing, not decorative.
fn escape(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_log() -> AuditLog {
        AuditLog {
            path: None,
            params: Params {
                mode: "dry-run",
                purge_mode: "multi-tenant",
                wallet_id: "w".into(),
                ttl_days: "30".into(),
                stale_ttl_days: String::new(),
                purge_stale_incomplete: "false".into(),
                throttle_ms: "250".into(),
                heartbeat_every: "20".into(),
                bulk_purge_batch_size: "500".into(),
                orphan_scan_batch_size: "2000".into(),
                orphan_delete_batch_size: "500".into(),
                db_max_connections: "50".into(),
                server_side_delete: "false".into(),
            },
        }
    }

    #[test]
    fn header_and_fields_stay_in_step() {
        let row = AuditRow::new("purge", "tenant-x", Utc::now());
        assert_eq!(
            test_log().fields(&row).len(),
            HEADER.len(),
            "column count drifted from HEADER"
        );
    }

    #[test]
    fn totals_include_cascaded_children() {
        let c = Counts {
            credentials_parents: 10,
            credentials_children: 30,
            proofs_parents: 5,
            proofs_children: 15,
            oob: 2,
            orphans: 100,
            basic_messages: 1,
            question_answers: 1,
            };
        assert_eq!(c.total(), 164);
    }

    #[test]
    fn csv_escaping() {
        assert_eq!(escape("plain"), "plain");
        assert_eq!(escape("a,b"), "\"a,b\"");
        assert_eq!(escape("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(escape("line\nbreak"), "\"line\nbreak\"");
    }

    #[test]
    fn writes_header_once_then_appends() {
        let dir = std::env::temp_dir().join(format!("credo-audit-{}", std::process::id()));
        let path = dir.join("nested").join("purge-audit.csv");
        let _ = std::fs::remove_dir_all(&dir);

        let mut log = test_log();
        log.path = Some(path.clone());

        let counts = Counts { credentials_parents: 7, orphans: 3, ..Default::default() };
        log.record(&AuditRow::new("purge", "tenant-a", Utc::now()).counts(counts));
        log.record(&AuditRow::new("purge", "tenant-b", Utc::now()).failed("db timeout, retrying"));

        let body = std::fs::read_to_string(&path).expect("audit file should exist");
        let lines: Vec<&str> = body.lines().collect();

        // Header written once, on creation, and the parent directory created for us.
        assert_eq!(lines.len(), 3, "expected header + 2 rows, got: {body}");
        assert_eq!(lines[0], HEADER.join(","));
        assert!(lines[1].contains("tenant-a"));
        assert!(lines[1].contains(",ok,"));
        // total_records = 7 credentials + 3 orphans
        assert!(lines[1].ends_with(",10,"), "row was: {}", lines[1]);
        assert!(lines[2].contains("tenant-b"));
        assert!(lines[2].contains(",failed,"));
        // The comma inside the error message must not create a column.
        assert!(lines[2].ends_with("\"db timeout, retrying\""), "row was: {}", lines[2]);
        assert_eq!(
            lines[1].matches(',').count() + 1,
            HEADER.len(),
            "ok row column count"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn error_rows_carry_the_message() {
        let row = AuditRow::new("purge", "t1", Utc::now()).failed("boom, it broke");
        let fields = test_log().fields(&row);
        assert_eq!(fields[4], "failed");
        assert_eq!(fields.last().unwrap(), "boom, it broke");
        // and it survives escaping intact
        assert_eq!(escape(fields.last().unwrap()), "\"boom, it broke\"");
    }
}
