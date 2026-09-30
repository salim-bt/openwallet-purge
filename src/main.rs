//! owpurge — Askar wallet pruning for a multi-tenant SSI platform.
//!
//! A single static binary: one env-var contract, stable log shapes, and safety gates
//! that default to refusing rather than deleting.
//!
//! It talks to the Askar store directly. That is not a shortcut around the agent
//! framework — it is what the framework itself does, since its storage service is a
//! thin pass-through over `session.remove` / `Scan` on this same library. See
//! `credo.rs` for every record constant this depends on and where it was read from.
//!
//! This tool only ever DELETES. It never writes a record, which is what makes the port
//! safe: Credo's serialization and tag-transform logic — the only part of the storage
//! shim with real behaviour — is on the write path and is never reached.

mod audit;
mod bulk_purge;
mod cascade;
mod census;
mod checkpoint;
mod config;
mod credo;
mod deletes;
mod orphans;
mod progress;
mod scan;
mod store;

use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use aries_askar::Store;
use clap::{Parser, Subcommand};

use audit::{AuditLog, AuditRow, Counts};
use cascade::PurgeStats;
use config::{Config, PurgeMode};

#[derive(Parser)]
#[command(
    name = "owpurge",
    about = "Prune stale exchange records from a Credo/Askar wallet",
    long_about = None,
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Collapse an eligible track into a single server-side DELETE instead of
    /// round-tripping record ids.
    ///
    /// Only applies where the whole (category, state) set is eligible — i.e.
    /// TTL_DAYS=0 — and never to the non-reusable OOB track. An age filter reads
    /// `updatedAt`, which lives inside the encrypted record value rather than in a
    /// tag, so it cannot be expressed in SQL; with any TTL > 0 this flag is ignored
    /// and the normal scan-then-delete path runs. Off by default.
    #[arg(long, global = true)]
    server_side_delete: bool,

    /// Do not append to the CSV audit trail.
    ///
    /// By default every purge appends one row per target to AUDIT_CSV
    /// (default ./logs/purge-audit.csv): when it ran, the parameters it ran with, and
    /// how many records of each category it removed.
    #[arg(long, global = true)]
    no_audit: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Read-only per-category record counts.
    Census,
    /// Full drain: all categories, all tenants, with checkpoint/resume.
    Purge,
    /// Fast parent-only purge with no child cascade.
    ///
    /// Requires DRY_RUN=false AND BULK_CONFIRM=true to execute live deletes.
    /// Always follow it with `orphan-sweep` on the same tenant.
    BulkPurge,
    /// Delete DidCommMessageRecords whose parent exchange is gone.
    OrphanSweep,
    /// Terminal credential exchanges + their message children.
    Credentials,
    /// Terminal proof exchanges + their message children.
    Proofs,
    /// Out-of-band invitations.
    Oob,
    /// Basic messages.
    BasicMessages,
    /// Question-answer records.
    QuestionAnswer,
    /// List every tenant id registered in the wallet.
    Tenants,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Fatal error: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<std::process::ExitCode> {
    let cli = Cli::parse();
    let cfg = Config::from_env()?;

    println!("\nowpurge  —  {}", command_name(&cli.command));
    println!("Mode    : {}", match cfg.purge_mode {
        PurgeMode::Dedicated => "dedicated",
        PurgeMode::MultiTenant => "multi-tenant",
    });
    cfg.banner();

    // Blocked modes are refused before the store is opened, so a blocked run cannot
    // reach a database at all.
    cfg.assert_mode_allowed()?;

    // Second safety gate for bulk-purge, on top of DRY_RUN=false.
    if matches!(cli.command, Command::BulkPurge) && !cfg.dry_run && !cfg.bulk_confirm {
        bail!(
            "bulk-purge requires BOTH DRY_RUN=false AND BULK_CONFIRM=true to execute live deletes."
        );
    }

    let audit = AuditLog::new(&cfg, !cli.no_audit, cli.server_side_delete);
    match audit.path_display() {
        Some(p) => println!("AUDIT   : {p}"),
        None => println!("AUDIT   : disabled (--no-audit)"),
    }

    let store = store::open(&cfg).await?;
    let result = dispatch(&store, &cfg, &cli, &audit).await;
    // Always close cleanly so the pool drains and Postgres doesn't see abandoned
    // connections, on the error path as much as the success path.
    let _ = store.close().await;
    result
}

fn command_name(c: &Command) -> &'static str {
    match c {
        Command::Census => "census (read-only)",
        Command::Purge => "purge",
        Command::BulkPurge => "bulk-purge",
        Command::OrphanSweep => "orphan sweep",
        Command::Credentials => "credentials",
        Command::Proofs => "proofs",
        Command::Oob => "oob",
        Command::BasicMessages => "basic messages",
        Command::QuestionAnswer => "question-answer",
        Command::Tenants => "tenants",
    }
}

/// Resolve the single target for the per-tenant commands.
///
/// In dedicated mode that is the root profile; in multi-tenant mode TENANT_ID is
/// required rather than defaulted, so a single-target command can never silently
/// address the wrong tenant.
fn single_target(cfg: &Config, command: &str) -> Result<(Option<String>, String)> {
    match cfg.purge_mode {
        PurgeMode::Dedicated => Ok((None, "root".to_string())),
        PurgeMode::MultiTenant => {
            let Some(id) = cfg.tenant_id.clone() else {
                bail!(
                    "TENANT_ID env var is required for {command} in multi-tenant mode. \
                     Use `owpurge purge` to process multiple tenants automatically."
                );
            };
            Ok((Some(credo::tenant_profile(&id)), id))
        }
    }
}

/// Record the outcome of a single-target command and pass the result through.
///
/// Every purge path funnels through here so a failure is audited too: a row with
/// `status=failed` and the error text. A gap in the file would be indistinguishable
/// from "never attempted".
fn finish(
    audit: &AuditLog,
    command: &str,
    label: &str,
    started: DateTime<Utc>,
    result: Result<PurgeStats>,
    to_counts: impl FnOnce(PurgeStats) -> Counts,
) -> Result<PurgeStats> {
    match result {
        Ok(stats) => {
            audit.record(&AuditRow::new(command, label, started).counts(to_counts(stats)));
            Ok(stats)
        }
        Err(e) => {
            audit.record(&AuditRow::new(command, label, started).failed(format!("{e:#}")));
            Err(e)
        }
    }
}

fn verb(dry_run: bool) -> &'static str {
    if dry_run {
        "eligible"
    } else {
        "deleted"
    }
}

async fn dispatch(
    store: &Store,
    cfg: &Config,
    cli: &Cli,
    audit: &AuditLog,
) -> Result<std::process::ExitCode> {
    let started = Utc::now();

    match &cli.command {
        Command::Tenants => {
            let ids = store::list_tenants(store).await?;
            println!("\nFound {} tenants:", ids.len());
            for id in &ids {
                println!("  {id}");
            }
        }

        // Read-only, so nothing is audited — the CSV is a record of deletions.
        Command::Census => {
            let (profile, label) = single_target(cfg, "census")?;
            census::run(store, cfg, profile, &label).await?;
        }

        Command::BulkPurge => {
            let (profile, label) = single_target(cfg, "bulk-purge")?;
            match bulk_purge::run(store, cfg, profile, &label, cli.server_side_delete).await {
                Ok(stats) => {
                    bulk_purge::print_summary(&label, &stats, cfg.dry_run);
                    let counts = Counts::default()
                        .with_credentials(stats.credentials)
                        .with_proofs(stats.proofs)
                        .with_oob(stats.oob);
                    audit.record(&AuditRow::new("bulk-purge", &label, started).counts(counts));
                }
                Err(e) => {
                    audit.record(
                        &AuditRow::new("bulk-purge", &label, started).failed(format!("{e:#}")),
                    );
                    return Err(e);
                }
            }
        }

        Command::OrphanSweep => {
            let (profile, label) = single_target(cfg, "orphan-sweep")?;
            let s = finish(
                audit,
                "orphan-sweep",
                &label,
                started,
                orphans::purge_orphans(store, cfg, profile, &label).await,
                |s| Counts::default().with_orphans(s),
            )?;
            println!(
                "\nDidCommMessageRecord orphans {}: {}",
                if cfg.dry_run { "found" } else { "deleted" },
                s.parents
            );
        }

        Command::Credentials => {
            let (profile, label) = single_target(cfg, "credentials")?;
            let s = finish(
                audit,
                "credentials",
                &label,
                started,
                cascade::purge_credentials(store, cfg, profile, &label).await,
                |s| Counts::default().with_credentials(s),
            )?;
            println!(
                "\nCredential exchange records {}: {} parents, {} DidCommMessage children",
                verb(cfg.dry_run),
                s.parents,
                s.children
            );
        }

        Command::Proofs => {
            let (profile, label) = single_target(cfg, "proofs")?;
            let s = finish(
                audit,
                "proofs",
                &label,
                started,
                cascade::purge_proofs(store, cfg, profile, &label).await,
                |s| Counts::default().with_proofs(s),
            )?;
            println!(
                "\nProof exchange records {}: {} parents, {} DidCommMessage children",
                verb(cfg.dry_run),
                s.parents,
                s.children
            );
        }

        Command::Oob => {
            let (profile, label) = single_target(cfg, "oob")?;
            let s = finish(
                audit,
                "oob",
                &label,
                started,
                cascade::purge_oob(store, cfg, profile, &label).await,
                |s| Counts::default().with_oob(s),
            )?;
            println!("\nOOB records {}: {}", verb(cfg.dry_run), s.parents);
        }

        Command::BasicMessages => {
            let (profile, label) = single_target(cfg, "basic-messages")?;
            let s = finish(
                audit,
                "basic-messages",
                &label,
                started,
                cascade::purge_basic_messages(store, cfg, profile, &label).await,
                |s| Counts::default().with_basic_messages(s),
            )?;
            println!("\nBasic messages {}: {}", verb(cfg.dry_run), s.parents);
        }

        Command::QuestionAnswer => {
            let (profile, label) = single_target(cfg, "question-answer")?;
            let s = finish(
                audit,
                "question-answer",
                &label,
                started,
                cascade::purge_question_answer(store, cfg, profile, &label).await,
                |s| Counts::default().with_question_answers(s),
            )?;
            println!("\nQuestion-answer records {}: {}", verb(cfg.dry_run), s.parents);
        }

        Command::Purge => return run_full_purge(store, cfg, audit).await,
    }

    Ok(std::process::ExitCode::SUCCESS)
}

#[derive(Debug, Default)]
struct TenantSummary {
    credentials: PurgeStats,
    proofs: PurgeStats,
    oob: PurgeStats,
    orphans: PurgeStats,
    basic_messages: PurgeStats,
    question_answers: PurgeStats,
}

impl TenantSummary {
    fn add(&mut self, other: &TenantSummary) {
        self.credentials.add(other.credentials);
        self.proofs.add(other.proofs);
        self.oob.add(other.oob);
        self.orphans.add(other.orphans);
        self.basic_messages.add(other.basic_messages);
        self.question_answers.add(other.question_answers);
    }

    fn counts(&self) -> Counts {
        Counts::default()
            .with_credentials(self.credentials)
            .with_proofs(self.proofs)
            .with_oob(self.oob)
            .with_orphans(self.orphans)
            .with_basic_messages(self.basic_messages)
            .with_question_answers(self.question_answers)
    }

    fn print(&self, label: &str) {
        println!("\n[{label}] Summary:");
        println!(
            "  Credentials    : {} parents, {} children",
            self.credentials.parents, self.credentials.children
        );
        println!(
            "  Proofs         : {} parents, {} children",
            self.proofs.parents, self.proofs.children
        );
        println!("  OOB            : {}", self.oob.parents);
        println!("  Orphans        : {}", self.orphans.parents);
        println!("  Basic messages : {}", self.basic_messages.parents);
        println!("  Q&A            : {}", self.question_answers.parents);
    }
}

/// Every purge category for one target, in dependency order.
async fn purge_all(
    store: &Store,
    cfg: &Config,
    profile: Option<String>,
    label: &str,
) -> Result<TenantSummary> {
    Ok(TenantSummary {
        credentials: cascade::purge_credentials(store, cfg, profile.clone(), label).await?,
        proofs: cascade::purge_proofs(store, cfg, profile.clone(), label).await?,
        oob: cascade::purge_oob(store, cfg, profile.clone(), label).await?,
        orphans: orphans::purge_orphans(store, cfg, profile.clone(), label).await?,
        basic_messages: cascade::purge_basic_messages(store, cfg, profile.clone(), label).await?,
        question_answers: cascade::purge_question_answer(store, cfg, profile, label).await?,
    })
}

async fn run_full_purge(
    store: &Store,
    cfg: &Config,
    audit: &AuditLog,
) -> Result<std::process::ExitCode> {
    if cfg.purge_mode == PurgeMode::Dedicated {
        let started = Utc::now();
        let mut session = store.session(None).await?;
        store::preflight(&mut session, "root").await?;
        drop(session);

        match purge_all(store, cfg, None, "root").await {
            Ok(summary) => {
                summary.print("root");
                audit.record(&AuditRow::new("purge", "root", started).counts(summary.counts()));
            }
            Err(e) => {
                audit.record(&AuditRow::new("purge", "root", started).failed(format!("{e:#}")));
                return Err(e);
            }
        }
        return Ok(std::process::ExitCode::SUCCESS);
    }

    // ── Multi-tenant ─────────────────────────────────────────────────────────
    let tenant_ids: Vec<String> = match (&cfg.tenant_allowlist, &cfg.tenant_id) {
        (Some(list), _) if !list.is_empty() => {
            println!("\nTenant allowlist ({}): {}", list.len(), list.join(", "));
            list.clone()
        }
        (_, Some(id)) => {
            println!("\nSingle tenant: {id}");
            vec![id.clone()]
        }
        _ => {
            println!("\nEnumerating all tenants...");
            let ids = store::list_tenants(store).await?;
            println!("Found {} tenants", ids.len());
            ids
        }
    };

    let mut cp = checkpoint::Checkpoint::load(cfg);
    let pending: Vec<String> = tenant_ids
        .iter()
        .filter(|id| !cp.contains(id))
        .cloned()
        .collect();

    if pending.len() < tenant_ids.len() {
        println!(
            "Resuming — {} tenant(s) already complete, {} remaining (checkpoint: {})",
            tenant_ids.len() - pending.len(),
            pending.len(),
            cp.display_path()
        );
    }

    let mut grand_total = TenantSummary::default();

    for tenant_id in &pending {
        println!("\n{}", "=".repeat(60));
        println!("Tenant: {tenant_id}");
        println!("{}", "=".repeat(60));

        // Timed per tenant, so a row's started_at/finished_at bracket exactly that
        // tenant's work rather than the whole drain.
        let started = Utc::now();
        let profile = credo::tenant_profile(tenant_id);

        // An unknown tenant is skipped rather than fatal. Askar has no distinct
        // "no such tenant" error, so check the profile list instead.
        match store::profile_exists(store, &profile).await {
            Ok(false) => {
                eprintln!("  Tenant {tenant_id} not found in database — skipping");
                audit.record(
                    &AuditRow::new("purge", tenant_id, started)
                        .skipped("tenant has no Askar profile in this store"),
                );
                continue;
            }
            Ok(true) => {}
            Err(e) => {
                eprintln!("  ERROR listing profiles for tenant {tenant_id}: {e:#}");
                eprintln!("  Skipped — re-run to retry this tenant.");
                audit.record(
                    &AuditRow::new("purge", tenant_id, started).failed(format!("{e:#}")),
                );
                continue;
            }
        }

        match purge_all(store, cfg, Some(profile), tenant_id).await {
            Ok(summary) => {
                summary.print(tenant_id);
                // Audited BEFORE the checkpoint: if the process dies between the two,
                // the tenant is re-purged on the next run (idempotent, deletes are
                // already-gone tolerant) and the CSV shows both attempts. The reverse
                // order could checkpoint a tenant with no record that it ran.
                audit.record(
                    &AuditRow::new("purge", tenant_id, started).counts(summary.counts()),
                );
                grand_total.add(&summary);
                cp.completed_tenants.push(tenant_id.clone());
                // Only persist when actually deleting — a dry run reports but never
                // writes, so a later live run does not skip tenants it never touched.
                if !cfg.dry_run {
                    cp.save()?;
                }
            }
            Err(e) => {
                // Transient failure (DB timeout, connection reset, a poison record).
                // Log and continue so the rest of the drain is not aborted. The tenant
                // is NOT checkpointed and is retried on the next run.
                eprintln!("  ERROR purging tenant {tenant_id}: {e:#}");
                eprintln!("  Skipped — re-run to retry this tenant.");
                audit.record(&AuditRow::new("purge", tenant_id, started).failed(format!("{e:#}")));
            }
        }
    }

    println!("\n{}", "=".repeat(60));
    println!("Grand total across all tenants:");
    grand_total.print("all");
    // Deliberately NOT audited as its own row: the per-tenant rows above already sum
    // to this, and a total row would double-count any SUM() over the column.
    if let Some(path) = audit.path_display() {
        println!("Audit rows appended to {path}");
    }

    if !cfg.dry_run && !pending.is_empty() {
        let incomplete: Vec<&String> = tenant_ids.iter().filter(|id| !cp.contains(id)).collect();
        if incomplete.is_empty() {
            println!("\nAll {} tenant(s) complete.", cp.completed_tenants.len());
            cp.remove();
            println!("Checkpoint file removed.");
        } else {
            eprintln!(
                "\n{} tenant(s) did not complete: {}",
                incomplete.len(),
                incomplete
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            eprintln!("Checkpoint kept — re-run to retry the incomplete tenant(s).");
            return Ok(std::process::ExitCode::FAILURE);
        }
    }

    Ok(std::process::ExitCode::SUCCESS)
}
