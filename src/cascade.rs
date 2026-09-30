//! The per-category purges with their DidCommMessage cascade.
//!
//! A credential or proof exchange has 3-6 `DidCommMessageRecord` children (the raw
//! DIDComm protocol payloads) linked by the `associatedRecordId` tag. They are deleted
//! before the parent so no orphan rows are left behind, and the dry-run counts them
//! too, so the reported total reflects actual row reduction rather than parent count.
//!
//! Children are resolved a batch at a time rather than a parent at a time. Because
//! `associatedRecordId` is a real Askar tag, a whole batch of 100 parents goes in a
//! single `any_of` query — one round trip instead of 100, with no dependence on the
//! connection pool being wide enough to run them in parallel.

use std::collections::HashMap;

use anyhow::Result;
use aries_askar::entry::TagFilter;
use aries_askar::Store;

use crate::config::Config;
use crate::credo::{category, tag, RecordValue, OOB_STATE_AWAIT_RESPONSE, OOB_STATE_DONE, TERMINAL_STATES};
use crate::deletes::{delete_ids, delete_pairs, throttle};
use crate::scan;

/// Parents per cascade batch.
const BATCH_SIZE: usize = 100;

#[derive(Debug, Default, Clone, Copy)]
pub struct PurgeStats {
    pub parents: u64,
    pub children: u64,
}

impl PurgeStats {
    pub fn add(&mut self, other: PurgeStats) {
        self.parents += other.parents;
        self.children += other.children;
    }
}

fn mode(dry_run: bool) -> &'static str {
    if dry_run {
        "DRY"
    } else {
        "DEL"
    }
}

/// Scan one category (optionally filtered by state) and collect the ids of records
/// past the TTL cutoff.
#[allow(clippy::too_many_arguments)]
async fn eligible_ids(
    store: &Store,
    cfg: &Config,
    profile: Option<String>,
    label: &str,
    category: &str,
    category_label: &str,
    state: Option<&str>,
    cutoff: chrono::DateTime<chrono::Utc>,
    exclude_reusable: bool,
) -> Result<Vec<String>> {
    let tag_filter = state.map(|s| TagFilter::is_eq(tag::STATE, s));
    let mut ids = Vec::new();

    scan::for_each(
        store,
        profile,
        category,
        tag_filter,
        label,
        category_label,
        cfg.heartbeat_every,
        BATCH_SIZE,
        cfg.dry_run,
        |entry| {
            let value: RecordValue = serde_json::from_slice(entry.value.as_ref()).unwrap_or_default();
            if !value.older_than(cutoff) {
                return Ok(false);
            }
            // A reusable await-response invitation is a live invitation URL. Never
            // delete it. `reusable` is not a tag, so this can only be checked here.
            if exclude_reusable && value.reusable == Some(true) {
                return Ok(false);
            }
            ids.push(entry.name.clone());
            Ok(true)
        },
    )
    .await?;

    Ok(ids)
}

/// Fetch the DidCommMessage children of a whole batch of parents in one query, keyed
/// by parent id.
async fn children_for(
    store: &Store,
    profile: Option<String>,
    parent_ids: &[String],
) -> Result<HashMap<String, Vec<String>>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    if parent_ids.is_empty() {
        return Ok(map);
    }

    let filter = TagFilter::any_of(
        parent_ids
            .iter()
            .map(|id| TagFilter::is_eq(tag::ASSOCIATED_RECORD_ID, id.as_str()))
            .collect(),
    );

    let mut session = store.session(profile).await?;
    let entries = session
        .fetch_all(
            Some(category::DIDCOMM_MESSAGE),
            Some(filter),
            None,
            None,
            false,
            false,
        )
        .await?;

    for entry in entries {
        // Prefer the tag; fall back to the value for a record that somehow lacks it.
        let parent = scan::tag_value(&entry, tag::ASSOCIATED_RECORD_ID)
            .map(|s| s.to_string())
            .or_else(|| {
                serde_json::from_slice::<RecordValue>(entry.value.as_ref())
                    .ok()
                    .and_then(|v| v.associated_record_id)
            });
        if let Some(parent) = parent {
            map.entry(parent).or_default().push(entry.name);
        }
    }
    Ok(map)
}

/// Delete terminal exchange records older than the TTL, cascading to their children.
///
/// Shared by credentials and proofs: the two flows differ only in the category, so
/// they run through one function rather than two near-identical copies.
async fn purge_exchange(
    store: &Store,
    cfg: &Config,
    profile: Option<String>,
    label: &str,
    category: &'static str,
    category_label: &str,
) -> Result<PurgeStats> {
    let mut stats = PurgeStats::default();

    for state in TERMINAL_STATES {
        println!("\n[{label}] {category_label} — state: {state}");

        let eligible = eligible_ids(
            store,
            cfg,
            profile.clone(),
            label,
            category,
            category_label,
            Some(state),
            cfg.delete_before,
            false,
        )
        .await?;

        let mut state_parents = 0u64;
        let mut state_children = 0u64;

        for (i, chunk) in eligible.chunks(BATCH_SIZE).enumerate() {
            let children = children_for(store, profile.clone(), chunk).await?;
            let batch_children: usize = children.values().map(|v| v.len()).sum();

            if !cfg.dry_run {
                // Children first, then the parent, so no orphan rows are left behind.
                let mut pairs: Vec<(&str, String)> = Vec::with_capacity(batch_children + chunk.len());
                for parent in chunk {
                    if let Some(kids) = children.get(parent) {
                        for kid in kids {
                            pairs.push((category::DIDCOMM_MESSAGE, kid.clone()));
                        }
                    }
                    pairs.push((category, parent.clone()));
                }
                let outcome = delete_pairs(
                    store,
                    profile.clone(),
                    &pairs,
                    &format!("[{label}] {category_label} [{state}]"),
                    false,
                )
                .await?;
                outcome.report(category_label);
            }

            let done = (i * BATCH_SIZE) + chunk.len();
            state_parents += chunk.len() as u64;
            state_children += batch_children as u64;
            stats.parents += chunk.len() as u64;
            stats.children += batch_children as u64;

            println!(
                "  [{}] {} parents + {} children ({}/{})",
                mode(cfg.dry_run),
                chunk.len(),
                batch_children,
                done,
                eligible.len()
            );

            throttle(cfg.throttle_ms).await;
        }

        println!("  → state '{state}': {state_parents} parents, {state_children} children");
    }

    Ok(stats)
}

pub async fn purge_credentials(
    store: &Store,
    cfg: &Config,
    profile: Option<String>,
    label: &str,
) -> Result<PurgeStats> {
    purge_exchange(
        store,
        cfg,
        profile,
        label,
        category::CREDENTIAL_EXCHANGE,
        "Credentials",
    )
    .await
}

pub async fn purge_proofs(
    store: &Store,
    cfg: &Config,
    profile: Option<String>,
    label: &str,
) -> Result<PurgeStats> {
    purge_exchange(store, cfg, profile, label, category::PROOF_EXCHANGE, "Proofs").await
}

/// OOB records, per solution design §4.1:
///   Track 1 — state=done, any reusability, older than TTL
///   Track 2 — state=await-response, non-reusable only, older than TTL
///             (a reusable await-response is a live invitation URL — never delete)
pub async fn purge_oob(
    store: &Store,
    cfg: &Config,
    profile: Option<String>,
    label: &str,
) -> Result<PurgeStats> {
    let mut stats = PurgeStats::default();
    let tracks: [(&str, &str, bool); 2] = [
        ("done (terminal)", OOB_STATE_DONE, false),
        (
            "await-response (stuck, non-reusable)",
            OOB_STATE_AWAIT_RESPONSE,
            true,
        ),
    ];

    for (track_label, state, exclude_reusable) in tracks {
        println!("\n[{label}] OOB — {track_label}");

        let eligible = eligible_ids(
            store,
            cfg,
            profile.clone(),
            label,
            category::OUT_OF_BAND,
            "OOB",
            Some(state),
            cfg.delete_before,
            exclude_reusable,
        )
        .await?;

        let mut track_count = 0u64;
        for (i, chunk) in eligible.chunks(BATCH_SIZE).enumerate() {
            if !cfg.dry_run {
                let outcome = delete_ids(
                    store,
                    profile.clone(),
                    category::OUT_OF_BAND,
                    chunk,
                    &format!("[{label}] OOB [{track_label}]"),
                    false,
                )
                .await?;
                outcome.report("OOB");
            }
            let done = (i * BATCH_SIZE) + chunk.len();
            track_count += chunk.len() as u64;
            stats.parents += chunk.len() as u64;
            println!(
                "  [{}] {} records ({}/{})",
                mode(cfg.dry_run),
                chunk.len(),
                done,
                eligible.len()
            );
            throttle(cfg.throttle_ms).await;
        }
        println!("  → '{track_label}': {track_count}");
    }

    Ok(stats)
}

/// Records eligible purely by age, with no state filter.
async fn purge_by_age(
    store: &Store,
    cfg: &Config,
    profile: Option<String>,
    label: &str,
    category: &'static str,
    category_label: &str,
) -> Result<PurgeStats> {
    let mut stats = PurgeStats::default();
    println!("\n[{label}] {category_label}");

    let eligible = eligible_ids(
        store,
        cfg,
        profile.clone(),
        label,
        category,
        category_label,
        None,
        cfg.delete_before,
        false,
    )
    .await?;

    for (i, chunk) in eligible.chunks(BATCH_SIZE).enumerate() {
        if !cfg.dry_run {
            let outcome = delete_ids(
                store,
                profile.clone(),
                category,
                chunk,
                &format!("[{label}] {category_label}"),
                false,
            )
            .await?;
            outcome.report(category_label);
        }
        let done = (i * BATCH_SIZE) + chunk.len();
        stats.parents += chunk.len() as u64;
        println!(
            "  [{}] {} records ({}/{})",
            mode(cfg.dry_run),
            chunk.len(),
            done,
            eligible.len()
        );
        throttle(cfg.throttle_ms).await;
    }

    Ok(stats)
}

pub async fn purge_basic_messages(
    store: &Store,
    cfg: &Config,
    profile: Option<String>,
    label: &str,
) -> Result<PurgeStats> {
    purge_by_age(
        store,
        cfg,
        profile,
        label,
        category::BASIC_MESSAGE,
        "Basic messages",
    )
    .await
}

pub async fn purge_question_answer(
    store: &Store,
    cfg: &Config,
    profile: Option<String>,
    label: &str,
) -> Result<PurgeStats> {
    purge_by_age(
        store,
        cfg,
        profile,
        label,
        category::QUESTION_ANSWER,
        "Question-answer",
    )
    .await
}
