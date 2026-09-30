//! Bulk parent purge — the fast path for large tenants.
//!
//! Deletes terminal credential/proof/OOB parents older than the TTL WITHOUT the
//! per-parent child cascade, which is the dominant cost. Children become orphans that
//! the set-based sweep clears in one pass afterwards. Same TTL eligibility as the
//! normal purge, just a different decomposition of the work.
//!
//! Identify-then-delete is deliberately two passes, not interleaved: deleting rows
//! through a live scan cursor over the same category is unproven territory. The orphan
//! sweep's Phase B/Phase C split avoids it for the same reason and this mirrors that.

use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};

use anyhow::{Context, Result};
use aries_askar::entry::TagFilter;
use aries_askar::Store;
use chrono::{DateTime, Utc};

use crate::cascade::PurgeStats;
use crate::config::Config;
use crate::credo::{
    category, proof_incomplete_states, tag, RecordValue, OOB_STATE_AWAIT_RESPONSE, OOB_STATE_DONE,
    TERMINAL_STATES,
};
use crate::deletes::{delete_ids, remove_all, throttle};
use crate::progress::sanitize_label;
use crate::scan;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bucket {
    Credentials,
    Proofs,
    Oob,
}

struct Track {
    label: String,
    category: &'static str,
    state: &'static str,
    bucket: Bucket,
    exclude_reusable: bool,
    /// Age cutoff. Terminal tracks use `delete_before`; stale-incomplete tracks use
    /// the separate, more conservative `stale_before`. Set at construction so the
    /// loop body needs no branching and a third tier is just a new cutoff value.
    cutoff: DateTime<Utc>,
    /// The TTL that produced `cutoff`, kept so the server-side fast path can tell
    /// whether the age filter is actually a no-op.
    ttl_days: i64,
}

#[derive(Debug, Default)]
pub struct BulkPurgeStats {
    pub credentials: PurgeStats,
    pub proofs: PurgeStats,
    pub oob: PurgeStats,
}

fn tracks(cfg: &Config) -> Vec<Track> {
    let mut out = Vec::new();

    for state in TERMINAL_STATES {
        out.push(Track {
            label: format!("Credentials [{state}]"),
            category: category::CREDENTIAL_EXCHANGE,
            state,
            bucket: Bucket::Credentials,
            exclude_reusable: false,
            cutoff: cfg.delete_before,
            ttl_days: cfg.ttl_days,
        });
    }
    for state in TERMINAL_STATES {
        out.push(Track {
            label: format!("Proofs [{state}]"),
            category: category::PROOF_EXCHANGE,
            state,
            bucket: Bucket::Proofs,
            exclude_reusable: false,
            cutoff: cfg.delete_before,
            ttl_days: cfg.ttl_days,
        });
    }
    out.push(Track {
        label: "OOB [done]".into(),
        category: category::OUT_OF_BAND,
        state: OOB_STATE_DONE,
        bucket: Bucket::Oob,
        exclude_reusable: false,
        cutoff: cfg.delete_before,
        ttl_days: cfg.ttl_days,
    });
    out.push(Track {
        label: "OOB [await-response, non-reusable]".into(),
        category: category::OUT_OF_BAND,
        state: OOB_STATE_AWAIT_RESPONSE,
        bucket: Bucket::Oob,
        exclude_reusable: true,
        cutoff: cfg.delete_before,
        ttl_days: cfg.ttl_days,
    });

    // Non-terminal PROOF states only, and only when explicitly opted in.
    //
    // Credentials are intentionally excluded: a holder holding a pending offer can
    // still accept it after the stale TTL, and deleting the issuer's record while the
    // holder's offer-received record exists breaks the issuance with no recovery path
    // other than a fresh offer. For a national ID system that is unacceptable. Proof
    // stale records are safe — a rejected stale proof just needs a re-request.
    if cfg.purge_stale_incomplete {
        for state in proof_incomplete_states() {
            out.push(Track {
                label: format!("Proofs [{state}, stale-incomplete]"),
                category: category::PROOF_EXCHANGE,
                state,
                bucket: Bucket::Proofs,
                exclude_reusable: false,
                cutoff: cfg.stale_before,
                ttl_days: cfg.stale_incomplete_ttl_days,
            });
        }
    }

    out
}

/// Can this track be collapsed into a single server-side `DELETE ... WHERE`?
///
/// Only when the age filter is a genuine no-op (TTL 0) and there is no value-only
/// predicate to honour. See `deletes::remove_all` for why an age filter can never be
/// pushed into SQL.
fn server_side_eligible(track: &Track) -> bool {
    track.ttl_days == 0 && !track.exclude_reusable
}

#[allow(clippy::too_many_arguments)]
async fn run_track(
    store: &Store,
    cfg: &Config,
    profile: Option<String>,
    label: &str,
    track: &Track,
    stats: &mut BulkPurgeStats,
    server_side: bool,
) -> Result<()> {
    println!("\n[{label}] {}", track.label);

    let bucket = match track.bucket {
        Bucket::Credentials => &mut stats.credentials,
        Bucket::Proofs => &mut stats.proofs,
        Bucket::Oob => &mut stats.oob,
    };

    // ── Server-side fast path ────────────────────────────────────────────────
    if server_side && server_side_eligible(track) && !cfg.dry_run {
        let removed = remove_all(
            store,
            profile.clone(),
            track.category,
            Some(TagFilter::is_eq(tag::STATE, track.state)),
        )
        .await
        .with_context(|| format!("[{label}] {} — server-side remove_all failed", track.label))?;
        println!(
            "  [DEL] {removed} parents (no cascade) — single server-side statement, no ids round-tripped"
        );
        println!("  → '{}': {removed}", track.label);
        bucket.parents += removed.max(0) as u64;
        throttle(cfg.throttle_ms).await;
        return Ok(());
    }

    // ── Identify ─────────────────────────────────────────────────────────────
    let spill_path = format!(
        "./bulk-purge-ids-{}-{}.tmp",
        sanitize_label(label),
        sanitize_label(&track.label)
    );
    let mut spill: Option<BufWriter<File>> = if cfg.dry_run {
        None
    } else {
        Some(BufWriter::new(File::create(&spill_path).with_context(
            || format!("could not create spill file {spill_path}"),
        )?))
    };

    let mut eligible_count: u64 = 0;
    let mut io_error: Option<std::io::Error> = None;

    let scanned = scan::for_each(
        store,
        profile.clone(),
        track.category,
        Some(TagFilter::is_eq(tag::STATE, track.state)),
        label,
        &track.label,
        cfg.heartbeat_every,
        cfg.bulk_purge_batch_size,
        cfg.dry_run,
        |entry| {
            let value: RecordValue =
                serde_json::from_slice(entry.value.as_ref()).unwrap_or_default();
            if !value.older_than(track.cutoff) {
                return Ok(false);
            }
            if track.exclude_reusable && value.reusable == Some(true) {
                return Ok(false);
            }
            eligible_count += 1;
            if let Some(w) = spill.as_mut() {
                if let Err(e) = writeln!(w, "{}", entry.name) {
                    if io_error.is_none() {
                        io_error = Some(e);
                    }
                }
            }
            Ok(true)
        },
    )
    .await?;

    if let Some(w) = spill.as_mut() {
        w.flush().ok();
    }
    drop(spill);
    if let Some(e) = io_error {
        let _ = std::fs::remove_file(&spill_path);
        return Err(anyhow::Error::new(e)
            .context(format!("failed writing the spill file {spill_path}")));
    }

    println!(
        "  [{label}] {}: scan complete — {eligible_count} eligible of {} scanned",
        track.label, scanned
    );

    // ── Delete ───────────────────────────────────────────────────────────────
    let mut track_count = 0u64;
    if cfg.dry_run {
        track_count = eligible_count;
    } else {
        let result = delete_pass(
            store,
            cfg,
            profile,
            label,
            track,
            &spill_path,
            eligible_count,
            &mut track_count,
        )
        .await;
        let _ = std::fs::remove_file(&spill_path);
        result?;
    }

    println!("  → '{}': {track_count}", track.label);
    bucket.parents += track_count;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn delete_pass(
    store: &Store,
    cfg: &Config,
    profile: Option<String>,
    label: &str,
    track: &Track,
    spill_path: &str,
    eligible_count: u64,
    track_count: &mut u64,
) -> Result<()> {
    let batch_size = cfg.bulk_purge_batch_size.max(1);
    let total_batches = eligible_count.div_ceil(batch_size as u64);

    let reader = BufReader::new(
        File::open(spill_path).with_context(|| format!("could not reopen {spill_path}"))?,
    );
    let mut batch: Vec<String> = Vec::with_capacity(batch_size);
    let mut batch_num = 0u64;

    for line in reader.lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        batch.push(line);
        if batch.len() >= batch_size {
            batch_num += 1;
            flush_batch(
                store, cfg, profile.clone(), label, track, &batch, batch_num, total_batches,
            )
            .await?;
            *track_count += batch.len() as u64;
            batch.clear();
        }
    }
    if !batch.is_empty() {
        batch_num += 1;
        flush_batch(
            store, cfg, profile, label, track, &batch, batch_num, total_batches,
        )
        .await?;
        *track_count += batch.len() as u64;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn flush_batch(
    store: &Store,
    cfg: &Config,
    profile: Option<String>,
    label: &str,
    track: &Track,
    batch: &[String],
    batch_num: u64,
    total_batches: u64,
) -> Result<()> {
    let outcome = delete_ids(
        store,
        profile,
        track.category,
        batch,
        &format!("[{label}] {}", track.label),
        false,
    )
    .await?;
    outcome.report(&track.label);
    println!(
        "  [DEL] {} parents (no cascade) (batch {batch_num}/{total_batches})",
        batch.len()
    );
    throttle(cfg.throttle_ms).await;
    Ok(())
}

pub async fn run(
    store: &Store,
    cfg: &Config,
    profile: Option<String>,
    label: &str,
    server_side: bool,
) -> Result<BulkPurgeStats> {
    let mut stats = BulkPurgeStats::default();

    // Fully sequential, deliberately. Same-category concurrency was trialled on
    // 2026-09-14: it ran clean on two tenants but coincided with a deep, sustained
    // scan-rate stall on a third (~250 rec/s against the ~5-10k rec/s seen on
    // already-cleared tenants) that did not recover on its own. Never conclusively
    // proven as the cause — cold cache / shared database load is at least as plausible
    // — but sequential is the known-safe baseline every successful run has used.
    for track in tracks(cfg) {
        run_track(store, cfg, profile.clone(), label, &track, &mut stats, server_side).await?;
    }

    Ok(stats)
}

pub fn print_summary(label: &str, stats: &BulkPurgeStats, dry_run: bool) {
    let mode = if dry_run {
        "eligible (dry-run)"
    } else {
        "deleted (no cascade)"
    };
    println!("\n[{label}] Bulk purge summary ({mode}):");
    println!("  Credentials : {} parents", stats.credentials.parents);
    println!("  Proofs      : {} parents", stats.proofs.parents);
    println!("  OOB         : {} parents", stats.oob.parents);
    println!("  NEXT STEP   : run `owpurge orphan-sweep` on tenant '{label}' to clear message children");
}
