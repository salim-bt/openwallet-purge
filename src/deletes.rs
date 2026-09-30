//! Batched deletes, with idempotency rules and safety guards.
//!
//! A batch is ONE transaction on ONE connection: N statements, one commit, one fsync.
//! The alternative — firing a batch as N concurrent single-record deletes — is N
//! autocommits contending for the connection pool, and degrades badly whenever the pool
//! is narrower than the batch size. One transaction avoids the contention entirely and
//! makes the batch atomic.

use anyhow::{bail, Result};
use aries_askar::entry::TagFilter;
use aries_askar::{ErrorKind, Store};

/// What happened to a batch.
#[derive(Debug, Default, Clone)]
pub struct BatchOutcome {
    pub deleted: usize,
    /// Rejected because the record was already gone. For a delete this is an
    /// idempotent success — the desired end state is reached — not a failure. Happens
    /// on re-runs, concurrent deletes, and duplicate ids from pagination.
    pub already_gone: usize,
    pub failed: usize,
    pub first_error: Option<String>,
}

impl BatchOutcome {
    /// Already-deleted counts as progress, so a re-run whose batch is entirely
    /// already-gone does NOT trip a false abort.
    pub fn progressed(&self) -> bool {
        self.deleted + self.already_gone > 0
    }

    pub fn report(&self, category: &str) {
        if self.already_gone > 0 {
            println!(
                "  {} {category} already deleted (skipped — idempotent).",
                self.already_gone
            );
        }
        if self.failed > 0 {
            eprintln!(
                "  {} {category} delete(s) failed: {}",
                self.failed,
                self.first_error.as_deref().unwrap_or("<no detail>")
            );
        }
    }
}

/// Delete `(category, name)` pairs in a single transaction.
///
/// `strict` mirrors the orphan sweep's Phase C, which throws on ANY real failure so
/// the tenant is not checkpointed as complete. Everywhere else only a batch with
/// *zero* progress aborts: that is the poison-record / lock guard, and it also stops an
/// infinite spin, since a scan-from-offset-0 loop would otherwise re-fetch the same
/// stuck records forever.
pub async fn delete_pairs(
    store: &Store,
    profile: Option<String>,
    pairs: &[(&str, String)],
    label: &str,
    strict: bool,
) -> Result<BatchOutcome> {
    let mut out = BatchOutcome::default();
    if pairs.is_empty() {
        return Ok(out);
    }

    let mut txn = store.transaction(profile).await?;
    for (category, name) in pairs {
        match txn.remove(category, name).await {
            Ok(()) => out.deleted += 1,
            Err(e) if e.kind() == ErrorKind::NotFound => out.already_gone += 1,
            Err(e) => {
                out.failed += 1;
                if out.first_error.is_none() {
                    out.first_error = Some(format!("{category}/{name}: {e}"));
                }
            }
        }
    }

    if !out.progressed() {
        // Nothing to commit and something is systemically wrong. Drop the transaction
        // (which rolls back) and stop rather than continue past it.
        let _ = txn.rollback().await;
        bail!(
            "{label}: 0/{} deletes succeeded — possible poison record or lock. Aborting. \
             First error: {}",
            pairs.len(),
            out.first_error.as_deref().unwrap_or("<no detail>")
        );
    }

    if strict && out.failed > 0 {
        let _ = txn.rollback().await;
        bail!(
            "{label}: {}/{} deletes failed — aborting so the tenant is not checkpointed as \
             complete. Re-run to retry. First error: {}",
            out.failed,
            pairs.len(),
            out.first_error.as_deref().unwrap_or("<no detail>")
        );
    }

    txn.commit().await?;
    Ok(out)
}

/// Convenience wrapper for a batch of ids that all share one category.
pub async fn delete_ids(
    store: &Store,
    profile: Option<String>,
    category: &'static str,
    ids: &[String],
    label: &str,
    strict: bool,
) -> Result<BatchOutcome> {
    let pairs: Vec<(&str, String)> = ids.iter().map(|id| (category, id.clone())).collect();
    delete_pairs(store, profile, &pairs, label, strict).await
}

/// Server-side bulk delete: one `DELETE ... WHERE` statement, no ids round-tripped.
///
/// This is the set-based path: Askar resolves the match server-side and deletes in
/// place, so no record ids cross the wire. It is the cheapest option for a large
/// target by a wide margin.
///
/// IT ONLY APPLIES WHERE THE WHOLE `(category, tag_filter)` SET IS ELIGIBLE. The TTL
/// predicate reads `updatedAt`, which lives inside the record's encrypted JSON value
/// and is NOT a tag (see credo::tag), so there is no WQL expression for "older than N
/// days" and no way to push an age filter into SQL. Callers must therefore only reach
/// this when `TTL_DAYS=0` collapses the age filter away, and never for the
/// non-reusable OOB track, whose `reusable` predicate is likewise value-only.
pub async fn remove_all(
    store: &Store,
    profile: Option<String>,
    category: &str,
    tag_filter: Option<TagFilter>,
) -> Result<i64> {
    let mut txn = store.transaction(profile).await?;
    let removed = txn.remove_all(Some(category), tag_filter).await?;
    txn.commit().await?;
    Ok(removed)
}

/// Sleep between batches to limit RDS load. `THROTTLE_MS=0` disables it.
pub async fn throttle(ms: u64) {
    if ms > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
    }
}
