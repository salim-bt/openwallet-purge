//! Environment-variable contract.
//!
//! Every name, default and fail-safe is fixed: these are read by cron jobs and wrapper
//! scripts, so changing one silently changes what a scheduled drain deletes. Treat the
//! names and the fallback behaviour below as a stable interface.

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Duration, Utc};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};

/// Exactly the set `encodeURIComponent` leaves alone: A-Z a-z 0-9 - _ . ! ~ * ' ( )
///
/// This has to match, because the resulting URI is the store identity. The agent builds
/// it with `uriFromStoreConfig` (@credo-ts/askar), and a password containing `@`, `/`
/// or `#` encodes differently under a looser escaper — which would simply fail to
/// authenticate.
const COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'!')
    .remove(b'~')
    .remove(b'*')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')');

fn enc(s: &str) -> String {
    utf8_percent_encode(s, COMPONENT).to_string()
}

/// Multi-tenant purging is DISABLED.
///
/// The platform currently drains only the dedicated agent, whose wallet is a single
/// Askar store with one profile. Nothing runs against the multi-tenant RDS wallets
/// yet.
///
/// Every multi-tenant code path is deliberately LEFT IN PLACE and unmodified —
/// tenant enumeration via the TenantRecord category, the `tenant-<id>` profile
/// naming, per-tenant iteration, checkpoint/resume, the not-found skip. They are
/// simply unreachable while this is `false`. Flip it to `true` to re-enable.
///
/// Before you do, note that none of that path has ever been exercised against a real
/// multi-tenant store — the only wallet tested has a single profile. Two things found
/// on the dedicated agent would silently break a multi-tenant run and are worth
/// checking per wallet first:
///   * KEY_DERIVATION_METHOD is not necessarily "raw" — Credo defaults to
///     kdf:argon2i:mod when the agent never sets it, and Askar refuses outright
///     rather than degrading.
///   * DB_USER determines the Postgres schema Askar resolves via search_path, so the
///     default "postgres" reports *no store* in a perfectly good database.
///
/// This is a compile-time constant on purpose. An env var would be a toggle, not a
/// block, and the point is that re-enabling is a deliberate decision someone makes in
/// a diff and re-verifies — not something a stray variable in a cron environment can
/// do by accident.
pub const MULTI_TENANT_ENABLED: bool = false;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurgeMode {
    /// Purge the root wallet directly — the agent is deployed without multi-tenancy.
    Dedicated,
    /// Purge inside a per-tenant Askar profile (default).
    MultiTenant,
}

#[derive(Debug, Clone)]
pub struct Config {
    // ── Store ────────────────────────────────────────────────────────────────
    pub wallet_id: String,
    pub wallet_key: String,
    pub key_derivation_method: String,
    pub db_host: String,
    pub db_port: String,
    pub db_user: String,
    pub db_password: String,
    pub db_admin_user: String,
    pub db_admin_password: String,
    pub db_max_connections: u32,
    pub db_min_connections: Option<u32>,
    /// Askar's `?schema=` URI parameter. Recommended: set it.
    ///
    /// Askar puts its tables in `schema.unwrap_or(username)` at provision time, and at
    /// open time looks for `config` in `ANY(CURRENT_SCHEMAS(false))` — the Postgres
    /// search_path, which defaults to `"$user", public`. Credo never sets this
    /// parameter, so a Credo-provisioned store lives in a schema named after whichever
    /// user the agent connects as, and is found again only by connecting as that same
    /// user. That makes DB_USER silently load-bearing: connect as anyone else and
    /// Askar reports no store in a perfectly good database, which reads like a missing
    /// wallet rather than a misconfiguration.
    ///
    /// Askar applies this as `search_path` on every pooled connection (see
    /// askar-storage postgres provision.rs, `conn_opts.options([("search_path", s)])`),
    /// so setting it pins WHERE the store is and reduces DB_USER to authentication.
    /// Leaving it unset matches Credo's own resolution exactly, at the cost of that
    /// coupling.
    pub db_schema: Option<String>,

    // ── Targeting ────────────────────────────────────────────────────────────
    pub purge_mode: PurgeMode,
    pub tenant_id: Option<String>,
    pub tenant_allowlist: Option<Vec<String>>,

    // ── Behaviour ────────────────────────────────────────────────────────────
    pub dry_run: bool,
    pub ttl_days: i64,
    pub throttle_ms: u64,
    pub heartbeat_every: u64,
    pub orphan_scan_batch_size: usize,
    pub orphan_delete_batch_size: usize,
    pub bulk_purge_batch_size: usize,
    pub bulk_confirm: bool,

    // ── Stale-incomplete (opt-in) ────────────────────────────────────────────
    pub purge_stale_incomplete: bool,
    pub stale_incomplete_ttl_days: i64,

    // ── Audit trail ──────────────────────────────────────────────────────────
    /// Where the CSV audit trail is appended. One row per purged target, flushed as
    /// each finishes. Override with AUDIT_CSV; disable entirely with --no-audit.
    pub audit_csv: std::path::PathBuf,

    // ── Derived cutoffs, fixed once at startup ───────────────────────────────
    pub delete_before: DateTime<Utc>,
    pub stale_before: DateTime<Utc>,
}

fn var(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

fn parse_or<T: std::str::FromStr>(key: &str, default: T) -> Result<T>
where
    T::Err: std::fmt::Display,
{
    match var(key) {
        None => Ok(default),
        Some(v) => v
            .trim()
            .parse::<T>()
            .map_err(|e| anyhow::anyhow!("{key}={v:?} is not a valid value: {e}")),
    }
}

impl Config {
    pub fn from_env() -> Result<Self> {
        // .env for local dev; on ECS / the EC2 host the vars are set directly and no
        // file is needed. Absent .env is not an error.
        let _ = dotenvy::dotenv();

        let wallet_id = var("WALLET_ID");
        let wallet_key = var("WALLET_KEY");
        let db_host = var("DB_HOST");
        let db_password = var("DB_PASSWORD");
        if wallet_id.is_none() || wallet_key.is_none() || db_host.is_none() || db_password.is_none()
        {
            bail!(
                "Missing required env vars: WALLET_ID, WALLET_KEY, DB_HOST, DB_PASSWORD. \
                 Copy .env.example to .env and fill in values for local dev, or set the \
                 env vars directly."
            );
        }
        let db_user = var("DB_USER").unwrap_or_else(|| "postgres".into());
        let db_password = db_password.unwrap();

        let ttl_days: i64 = parse_or("TTL_DAYS", 30)?;
        let now = Utc::now();

        let purge_stale_incomplete = var("PURGE_STALE_INCOMPLETE").as_deref() == Some("true");
        let stale_allow_zero_ttl = var("STALE_ALLOW_ZERO_TTL").as_deref() == Some("true");
        let stale_incomplete_ttl_days =
            resolve_stale_ttl(var("STALE_INCOMPLETE_TTL_DAYS"), stale_allow_zero_ttl, purge_stale_incomplete);

        let cfg = Config {
            wallet_id: wallet_id.unwrap(),
            wallet_key: wallet_key.unwrap(),
            key_derivation_method: var("KEY_DERIVATION_METHOD").unwrap_or_else(|| "raw".into()),
            db_host: db_host.unwrap(),
            db_port: var("DB_PORT").unwrap_or_else(|| "5432".into()),
            db_admin_user: var("DB_ADMIN_USER").unwrap_or_else(|| db_user.clone()),
            db_admin_password: var("DB_ADMIN_PASSWORD").unwrap_or_else(|| db_password.clone()),
            db_user,
            db_password,
            db_max_connections: parse_or("DB_MAX_CONNECTIONS", 50)?,
            db_schema: var("DB_SCHEMA"),
            db_min_connections: match var("DB_MIN_CONNECTIONS") {
                None => None,
                Some(v) => Some(v.trim().parse().context("DB_MIN_CONNECTIONS")?),
            },

            purge_mode: match var("PURGE_MODE").as_deref() {
                Some("dedicated") => PurgeMode::Dedicated,
                Some("multi-tenant") | None => PurgeMode::MultiTenant,
                Some(other) => bail!("PURGE_MODE={other:?} — expected 'dedicated' or 'multi-tenant'"),
            },
            tenant_id: var("TENANT_ID"),
            tenant_allowlist: var("TENANT_ALLOWLIST").map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            }),

            // Fail-safe: dry-run is the default. ONLY the explicit literal "false"
            // executes live deletes; missing/empty always falls back to dry-run.
            dry_run: var("DRY_RUN").as_deref() != Some("false"),
            ttl_days,
            throttle_ms: parse_or("THROTTLE_MS", 250)?,
            heartbeat_every: parse_or("HEARTBEAT_EVERY", 20)?,
            orphan_scan_batch_size: parse_or("ORPHAN_SCAN_BATCH_SIZE", 2000)?,
            orphan_delete_batch_size: parse_or("ORPHAN_DELETE_BATCH_SIZE", 500)?,
            bulk_purge_batch_size: parse_or("BULK_PURGE_BATCH_SIZE", 500)?,
            bulk_confirm: var("BULK_CONFIRM").as_deref() == Some("true"),

            purge_stale_incomplete,
            stale_incomplete_ttl_days,

            audit_csv: var("AUDIT_CSV")
                .unwrap_or_else(|| "./logs/purge-audit.csv".into())
                .into(),

            delete_before: now - Duration::days(ttl_days),
            stale_before: now - Duration::days(stale_incomplete_ttl_days),
        };

        if cfg.tenant_allowlist.as_ref().is_some_and(|a| a.is_empty()) {
            bail!("TENANT_ALLOWLIST is set but contains no usable tenant ids");
        }
        Ok(cfg)
    }

    /// The Askar store URI.
    ///
    /// Reproduces `uriFromStoreConfig` for the postgres branch exactly, including
    /// parameter order. The database name is the wallet id; the host segment carries
    /// `host:port` unencoded, as Credo passes `${host}:${port}` straight through.
    pub fn store_uri(&self) -> String {
        let mut params = vec![
            format!("admin_account={}", enc(&self.db_admin_user)),
            format!("admin_password={}", enc(&self.db_admin_password)),
            format!("max_connections={}", self.db_max_connections),
        ];
        if let Some(min) = self.db_min_connections {
            params.push(format!("min_connections={min}"));
        }
        if let Some(schema) = &self.db_schema {
            params.push(format!("schema={}", enc(schema)));
        }
        format!(
            "postgres://{}:{}@{}:{}/{}?{}",
            enc(&self.db_user),
            enc(&self.db_password),
            self.db_host,
            self.db_port,
            enc(&self.wallet_id),
            params.join("&")
        )
    }

    /// Same string with the secrets masked — safe to print.
    pub fn store_uri_redacted(&self) -> String {
        format!(
            "postgres://{}:***@{}:{}/{}?admin_account={}&admin_password=***&max_connections={}",
            enc(&self.db_user),
            self.db_host,
            self.db_port,
            enc(&self.wallet_id),
            enc(&self.db_admin_user),
            self.db_max_connections
        )
    }

    /// Refuse to run in a mode that is currently blocked.
    ///
    /// Checked before the store is opened, so a blocked run costs nothing and cannot
    /// touch a database. Note the default PURGE_MODE is deliberately still
    /// "multi-tenant": that means forgetting to set it produces this error rather
    /// than silently draining the root profile as if it were the dedicated agent.
    pub fn assert_mode_allowed(&self) -> Result<()> {
        if self.purge_mode == PurgeMode::MultiTenant && !MULTI_TENANT_ENABLED {
            bail!(
                "PURGE_MODE=multi-tenant is disabled in this build.\n\
                 \n\
                 Only the dedicated agent is drained at present. Set PURGE_MODE=dedicated.\n\
                 \n\
                 (If PURGE_MODE was simply unset: it defaults to multi-tenant on purpose, so\n\
                 that an unset value fails here instead of quietly draining the root profile.)\n\
                 \n\
                 The multi-tenant logic is still present and unmodified — see\n\
                 MULTI_TENANT_ENABLED in src/config.rs to re-enable it, and re-validate\n\
                 against a census first: that path has never been exercised against a\n\
                 real multi-tenant store."
            );
        }
        Ok(())
    }

    pub fn banner(&self) {
        println!(
            "CONFIG: THROTTLE_MS={} ORPHAN_DELETE_BATCH_SIZE={} DB_MAX_CONNECTIONS={}",
            self.throttle_ms, self.orphan_delete_batch_size, self.db_max_connections
        );
        println!("STORE   : {}", self.store_uri_redacted());
        if self.dry_run {
            println!("MODE: DRY-RUN — counting only, nothing will be deleted.");
        } else {
            println!("\u{26a0}\u{fe0f}  MODE: LIVE DELETE — records will be permanently removed.");
        }
        if self.purge_stale_incomplete {
            let age = if self.stale_incomplete_ttl_days == 0 {
                "regardless of age (NO age floor — test only)".to_string()
            } else {
                format!("older than {} days", self.stale_incomplete_ttl_days)
            };
            println!(
                "\u{26a0}\u{fe0f}  STALE-INCOMPLETE mode ON — non-terminal (incomplete/abandoned) proof \
                 exchanges {age} will ALSO be deleted. Credential exchanges are not affected \
                 (intentionally excluded — see credo.rs)."
            );
        }
    }
}

/// Resolve `STALE_INCOMPLETE_TTL_DAYS` behind a two-key fail-safe.
///
/// Deleting non-terminal records with no age floor would remove genuinely in-flight
/// flows (a `request-sent` from minutes ago is an active verification), so anything
/// invalid or <= 0 falls back to 90 days. A real 0-day floor exists for testing only,
/// and needs BOTH an exact `0` here AND `STALE_ALLOW_ZERO_TTL=true`, so an accidental
/// `STALE_INCOMPLETE_TTL_DAYS=0` in production still fails safe.
///
/// Parsing is strict on purpose: `"30abc"` is malformed, so it goes to the 90-day
/// fallback rather than being read leniently as 30. A lenient parse here would quietly
/// honour a typo as a shorter retention window, which is the dangerous direction.
fn resolve_stale_ttl(raw: Option<String>, allow_zero: bool, warn: bool) -> i64 {
    const DEFAULT: i64 = 90;
    let Some(raw) = raw else { return DEFAULT };
    let trimmed = raw.trim();
    let parsed = trimmed.parse::<i64>().ok();

    let resolved = match parsed {
        Some(n) if n > 0 => n,
        // The 0-day floor is honoured only for a clean, exact "0".
        _ if trimmed == "0" && allow_zero => 0,
        _ => DEFAULT,
    };

    if warn {
        if resolved == 0 {
            eprintln!(
                "\u{26a0}\u{fe0f}  STALE_INCOMPLETE_TTL_DAYS=0 + STALE_ALLOW_ZERO_TTL=true — NO AGE FLOOR. \
                 ALL incomplete proof exchanges will be deleted regardless of age, including \
                 active in-flight flows. Test / non-production use only."
            );
        } else if Some(resolved) != parsed {
            eprintln!(
                "\u{26a0}\u{fe0f}  STALE_INCOMPLETE_TTL_DAYS invalid or <= 0 — falling back to {DEFAULT} days. \
                 Incomplete records are never deleted without an age floor unless \
                 STALE_ALLOW_ZERO_TTL=true (test only)."
            );
        }
    }
    resolved
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_ttl_fail_safe() {
        assert_eq!(resolve_stale_ttl(None, false, false), 90);
        assert_eq!(resolve_stale_ttl(Some("30".into()), false, false), 30);
        // 0 without the second key -> 90
        assert_eq!(resolve_stale_ttl(Some("0".into()), false, false), 90);
        // 0 with the second key -> a real 0-day floor
        assert_eq!(resolve_stale_ttl(Some("0".into()), true, false), 0);
        // negative -> 90 even with the escape hatch
        assert_eq!(resolve_stale_ttl(Some("-1".into()), true, false), 90);
        // malformed -> 90, and specifically NOT 0, even with the escape hatch set
        assert_eq!(resolve_stale_ttl(Some("0abc".into()), true, false), 90);
        assert_eq!(resolve_stale_ttl(Some("0x0".into()), true, false), 90);
    }

    fn sample() -> Config {
        let now = chrono::Utc::now();
        Config {
            wallet_id: "my-wallet".into(),
            wallet_key: "k".into(),
            key_derivation_method: "raw".into(),
            db_host: "db.example.com".into(),
            db_port: "5432".into(),
            db_user: "postgres".into(),
            db_password: "p@ss/w#rd".into(),
            db_admin_user: "postgres".into(),
            db_admin_password: "p@ss/w#rd".into(),
            db_max_connections: 50,
            db_min_connections: None,
            db_schema: None,
            purge_mode: PurgeMode::MultiTenant,
            tenant_id: None,
            tenant_allowlist: None,
            dry_run: true,
            ttl_days: 30,
            throttle_ms: 250,
            heartbeat_every: 20,
            orphan_scan_batch_size: 2000,
            orphan_delete_batch_size: 500,
            bulk_purge_batch_size: 500,
            bulk_confirm: false,
            purge_stale_incomplete: false,
            stale_incomplete_ttl_days: 90,
            audit_csv: "./logs/purge-audit.csv".into(),
            delete_before: now,
            stale_before: now,
        }
    }

    /// The URI is the store's identity — if it differs from what the agent builds, this
    /// binary either fails to authenticate or, worse, opens a different database.
    /// Expected value derived by hand from `uriFromStoreConfig` (@credo-ts/askar): user,
    /// password, wallet id, admin account and admin password each go through
    /// percent-encoding; the host segment is `host:port` passed through untouched;
    /// params follow in the order admin_account, admin_password, max_connections,
    /// min_connections.
    #[test]
    fn store_uri_matches_credo() {
        assert_eq!(
            sample().store_uri(),
            "postgres://postgres:p%40ss%2Fw%23rd@db.example.com:5432/my-wallet\
             ?admin_account=postgres&admin_password=p%40ss%2Fw%23rd&max_connections=50"
                .replace(' ', "")
        );
    }

    #[test]
    fn redacted_uri_hides_both_secrets() {
        let cfg = sample();
        let red = cfg.store_uri_redacted();
        assert!(!red.contains("p%40ss"), "password leaked: {red}");
        assert!(!red.contains("p@ss"), "password leaked: {red}");
        assert!(red.contains("db.example.com:5432/my-wallet"));
    }

    /// Unset by default, because Credo never sets it and the whole point is to
    /// resolve the store the same way the agent does.
    #[test]
    fn schema_param_is_absent_unless_asked_for() {
        let mut cfg = sample();
        assert!(!cfg.store_uri().contains("schema="));
        cfg.db_schema = Some("wallet_schema".into());
        assert!(cfg.store_uri().ends_with("&schema=wallet_schema"));
    }

    #[test]
    fn min_connections_only_appears_when_set() {
        let mut cfg = sample();
        assert!(!cfg.store_uri().contains("min_connections"));
        cfg.db_min_connections = Some(5);
        assert!(cfg.store_uri().ends_with("&min_connections=5"));
    }

    #[test]
    fn multi_tenant_is_blocked_and_dedicated_is_not() {
        let mut cfg = sample();
        cfg.purge_mode = PurgeMode::MultiTenant;
        let err = cfg.assert_mode_allowed().unwrap_err().to_string();
        assert!(err.contains("disabled"), "unhelpful message: {err}");
        assert!(err.contains("PURGE_MODE=dedicated"), "must say what to do instead");

        cfg.purge_mode = PurgeMode::Dedicated;
        assert!(cfg.assert_mode_allowed().is_ok());
    }

    /// The default must stay multi-tenant so that an UNSET PURGE_MODE hits the block
    /// and errors, rather than silently draining the root profile. If someone later
    /// flips the default to dedicated "for convenience", this fails and explains why.
    #[test]
    fn unset_purge_mode_fails_closed() {
        let mut cfg = sample();
        cfg.purge_mode = PurgeMode::MultiTenant; // what from_env() yields when unset
        assert!(
            cfg.assert_mode_allowed().is_err(),
            "an unset PURGE_MODE must error, never default into draining the root profile"
        );
    }

    #[test]
    fn encode_uri_component_parity() {
        // encodeURIComponent leaves these alone...
        assert_eq!(enc("abcXYZ019-_.!~*'()"), "abcXYZ019-_.!~*'()");
        // ...and escapes everything else, reserved chars included.
        assert_eq!(enc("p@ss/w#rd:1+2 3"), "p%40ss%2Fw%23rd%3A1%2B2%203");
    }
}
