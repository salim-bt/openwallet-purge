//! Set-based orphan sweep.
//!
//! Removes `DidCommMessageRecord` rows whose `associatedRecordId` points at an
//! exchange record that no longer exists. Needed on every drain because bulk-purge
//! deletes parents WITHOUT cascading to children — that is what makes it fast — so
//! this is the pass that clears what it leaves behind.
//!
//! Three phases:
//!   A. Pre-load every surviving parent id (credential + proof) into a set. No deletes.
//!      This MUST be complete: a parent missed here misclassifies its live children as
//!      orphans and deletes them.
//!   B. Stream every DidCommMessageRecord and identify orphans. Incompleteness here is
//!      low-stakes, unlike Phase A — a message missed this run is simply caught by the
//!      next sweep (the wrapper scripts run the sweep twice back-to-back for exactly
//!      that reason). Never a risk to live data.
//!   C. Delete the identified ids in batches, streamed back from the spill file.
//!
//! Race guard: a message created after the sweep started is never treated as an
//! orphan, even if its parent is absent from the Phase A snapshot.
//!
//! Phase B is cheap because `associatedRecordId` is a real Askar tag: the parent link
//! is read straight off `entry.tags`, and the JSON value is deserialized only for
//! actual orphan candidates — which, on a healthy wallet, is a small fraction of the
//! rows scanned.

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};

use anyhow::{Context, Result};
use aries_askar::Store;
use chrono::Utc;

use crate::cascade::PurgeStats;
use crate::config::Config;
use crate::credo::{category, tag, RecordValue};
use crate::deletes::{delete_ids, throttle};
use crate::progress::sanitize_label;
use crate::scan;

pub async fn purge_orphans(
    store: &Store,
    cfg: &Config,
    profile: Option<String>,
    label: &str,
) -> Result<PurgeStats> {
    let mut stats = PurgeStats::default();
    let run_start = Utc::now();

    println!("\n[{label}] Orphan sweep (set-based)");

    // ── Phase A ──────────────────────────────────────────────────────────────
    let mut parents: HashSet<String> = HashSet::new();
    for cat in [category::CREDENTIAL_EXCHANGE, category::PROOF_EXCHANGE] {
        scan::collect_ids(
            store,
            profile.clone(),
            cat,
            label,
            "Orphan sweep (Phase A)",
            cfg.heartbeat_every,
            cfg.orphan_scan_batch_size,
            &mut parents,
        )
        .await
        .with_context(|| {
            format!(
                "Phase A: error scanning {cat} after loading {} ids — orphan sweep aborted for [{label}]",
                parents.len()
            )
        })?;
    }
    println!("  Phase A: {} surviving parent IDs loaded", parents.len());

    // ── Phase B ──────────────────────────────────────────────────────────────
    let spill_path = format!("./orphan-ids-{}.tmp", sanitize_label(label));
    let mut spill: Option<BufWriter<File>> = if cfg.dry_run {
        None
    } else {
        Some(BufWriter::new(
            File::create(&spill_path)
                .with_context(|| format!("could not create spill file {spill_path}"))?,
        ))
    };

    let mut orphan_count: u64 = 0;
    let mut io_error: Option<std::io::Error> = None;

    let scanned_b = scan::for_each(
        store,
        profile.clone(),
        category::DIDCOMM_MESSAGE,
        None,
        label,
        "Orphan sweep",
        cfg.heartbeat_every,
        cfg.orphan_scan_batch_size,
        cfg.dry_run,
        |entry| {
            // Tag first — no deserialization on the hot path.
            let parent_id = match scan::tag_value(entry, tag::ASSOCIATED_RECORD_ID) {
                Some(v) => Some(v.to_string()),
                None => serde_json::from_slice::<RecordValue>(entry.value.as_ref())
                    .ok()
                    .and_then(|v| v.associated_record_id),
            };
            let Some(parent_id) = parent_id else {
                // No parent link at all — not an orphan by this definition.
                return Ok(false);
            };
            if parents.contains(&parent_id) {
                return Ok(false);
            }

            // Orphan candidate. Only now pay for the JSON, to apply the race guard.
            let value: RecordValue =
                serde_json::from_slice(entry.value.as_ref()).unwrap_or_default();
            if !value.predates(run_start) {
                return Ok(false);
            }

            orphan_count += 1;
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
        return Err(anyhow::Error::new(e)
            .context(format!("failed writing the orphan spill file {spill_path}")));
    }

    println!(
        "  Phase B: {orphan_count} orphans identified (scanned {} messages)",
        scanned_b
    );
    stats.parents = orphan_count;

    // ── Phase C ──────────────────────────────────────────────────────────────
    if cfg.dry_run {
        return Ok(stats);
    }

    let result = delete_from_spill(store, cfg, profile, label, &spill_path, orphan_count).await;
    // Always clean up the spill file, success or failure.
    let _ = std::fs::remove_file(&spill_path);
    result?;

    Ok(stats)
}

async fn delete_from_spill(
    store: &Store,
    cfg: &Config,
    profile: Option<String>,
    label: &str,
    spill_path: &str,
    orphan_count: u64,
) -> Result<()> {
    let batch_size = cfg.orphan_delete_batch_size.max(1);
    let total_batches = orphan_count.div_ceil(batch_size as u64);

    let file = File::open(spill_path)
        .with_context(|| format!("could not reopen spill file {spill_path}"))?;
    let reader = BufReader::new(file);

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
            flush_batch(store, cfg, profile.clone(), label, &batch, batch_num, total_batches).await?;
            batch.clear();
        }
    }
    if !batch.is_empty() {
        batch_num += 1;
        flush_batch(store, cfg, profile, label, &batch, batch_num, total_batches).await?;
    }

    Ok(())
}

async fn flush_batch(
    store: &Store,
    cfg: &Config,
    profile: Option<String>,
    label: &str,
    batch: &[String],
    batch_num: u64,
    total_batches: u64,
) -> Result<()> {
    // `strict`: any real failure aborts, so the per-tenant catch above keeps this
    // tenant OUT of the checkpoint and it is retried on the next run. Reporting a
    // partially-swept tenant as complete would leave orphans behind indefinitely.
    let outcome = delete_ids(
        store,
        profile,
        category::DIDCOMM_MESSAGE,
        batch,
        &format!("[{label}] Orphan sweep (batch {batch_num}/{total_batches})"),
        true,
    )
    .await?;
    outcome.report("orphan");
    println!(
        "  [DEL] {} orphans (batch {batch_num}/{total_batches})",
        batch.len()
    );
    throttle(cfg.throttle_ms).await;
    Ok(())
}
