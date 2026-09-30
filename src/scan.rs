//! One shared streaming scan, used by every purge path.
//!
//! One server-side cursor, rather than `{limit, offset}` paging. Two failure modes make
//! that the only safe shape:
//!
//!  1. `{limit, offset}` paging costs O(offset) per call — Askar walks and discards
//!     every already-skipped row on each separate query, so throughput collapses as
//!     offset grows (observed: ~1700 rec/s down to ~270 rec/s over the first 260k
//!     messages, with an offset reaching 18,981 after only 17,500 rows scanned).
//!  2. Askar gives no stable sort across *separate* scan calls, so page boundaries
//!     misalign and silently skip records (observed: 2885, then 3531, both short of
//!     the true count) — a wrong answer with no error attached.
//!
//! A single cursor fixes both: nothing is re-skipped and there are no page boundaries
//! to misalign. Two properties this relies on:
//!
//!  * `Scan` is a `Stream`, so each page drops when it goes out of scope and memory
//!    stays flat for the length of the scan.
//!  * `OrderBy::Id` is passed explicitly, so the cursor is deterministically ordered
//!    rather than relying on a single call having nothing to reorder around.

use anyhow::Result;
use aries_askar::entry::{Entry, TagFilter};
use aries_askar::storage::backend::OrderBy;
use aries_askar::Store;

use crate::progress::{db_wait, Heartbeat};

/// Stream every entry in `category` matching `tag_filter`, calling `f` on each.
///
/// Returns the number of records scanned. `f` returns whether the entry counted as
/// "affected" (eligible / identified), which
/// is what the heartbeat reports. `group_size` is purely a heartbeat-grouping unit —
/// with a single cursor there is no query page size to tune, so it only controls how
/// many scanned records make up one reported "batch".
#[allow(clippy::too_many_arguments)]
pub async fn for_each<F>(
    store: &Store,
    profile: Option<String>,
    category: &str,
    tag_filter: Option<TagFilter>,
    label: &str,
    category_label: &str,
    heartbeat_every: u64,
    group_size: usize,
    dry_run: bool,
    mut f: F,
) -> Result<u64>
where
    F: FnMut(&Entry) -> Result<bool>,
{
    let wait_label = format!("{label} — {category_label}");
    let mut hb = Heartbeat::new(label, category_label, heartbeat_every, dry_run);

    let mut scan = db_wait(
        &wait_label,
        store.scan(
            profile,
            Some(category.to_string()),
            tag_filter,
            None,
            None,
            Some(OrderBy::Id),
            false,
        ),
    )
    .await?;

    let group_size = group_size.max(1) as u64;
    let mut scanned: u64 = 0;
    let mut affected: u64 = 0;

    loop {
        let Some(page) = db_wait(&wait_label, scan.fetch_next()).await? else {
            break;
        };
        for entry in &page {
            if f(entry)? {
                affected += 1;
            }
            scanned += 1;
            if scanned % group_size == 0 {
                hb.batch(scanned, affected);
            }
        }
        // `page` drops here. No handle to free.
    }

    Ok(scanned)
}

/// Collect just the entry names (record ids) for a category.
///
/// Used by the orphan sweep's Phase A, where only ids are ever needed — no value is
/// deserialized at all. Deserializing a whole credential or proof record only to keep
/// its id is the dominant cost in that phase, so skipping it matters.
#[allow(clippy::too_many_arguments)]
pub async fn collect_ids(
    store: &Store,
    profile: Option<String>,
    category: &str,
    label: &str,
    category_label: &str,
    heartbeat_every: u64,
    group_size: usize,
    sink: &mut std::collections::HashSet<String>,
) -> Result<u64> {
    for_each(
        store,
        profile,
        category,
        None,
        label,
        category_label,
        heartbeat_every,
        group_size,
        true,
        |entry| {
            sink.insert(entry.name.clone());
            Ok(true)
        },
    )
    .await
}

/// Read a named tag off an entry, if present.
pub fn tag_value<'e>(entry: &'e Entry, name: &str) -> Option<&'e str> {
    entry
        .tags
        .iter()
        .find(|t| t.name() == name)
        .map(|t| t.value())
}
