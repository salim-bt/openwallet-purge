//! Progress output. The line shapes are a stable interface — runbooks and anything
//! grepping `logs/` depend on them, so treat a change here as a breaking change.

use std::future::Future;
use std::time::{Duration, Instant};

/// Emits a progress line every `every` batches so a long run is visibly alive even
/// while paging through records too recent to be eligible. Without it the console can
/// look frozen for long stretches on a large wallet.
pub struct Heartbeat {
    label: String,
    category: String,
    every: u64,
    dry_run: bool,
    start: Instant,
    batches: u64,
}

impl Heartbeat {
    pub fn new(label: &str, category: &str, every: u64, dry_run: bool) -> Self {
        Self {
            label: label.to_string(),
            category: category.to_string(),
            every: every.max(1),
            dry_run,
            start: Instant::now(),
            batches: 0,
        }
    }

    pub fn elapsed_secs(&self) -> u64 {
        self.start.elapsed().as_secs().max(1)
    }

    /// Count one batch and print if this is a heartbeat batch.
    pub fn batch(&mut self, scanned: u64, affected: u64) {
        self.batches += 1;
        if self.batches % self.every != 0 {
            return;
        }
        self.print(scanned, affected);
    }

    pub fn print(&self, scanned: u64, affected: u64) {
        let elapsed = self.elapsed_secs();
        let rate = scanned / elapsed;
        println!(
            "  \u{b7} [{}] {}: batch {}, scanned\u{2248}{}, {}\u{2248}{}, elapsed={}s (~{} rec/s)",
            self.label,
            self.category,
            self.batches,
            scanned,
            if self.dry_run { "eligible" } else { "deleted" },
            affected,
            elapsed,
            rate
        );
    }
}

/// Wrap a single DB call with a periodic "still waiting" log.
///
/// A genuinely slow query (10+ minutes has been observed on a large shared wallet DB
/// under contention — concurrent autovacuum, live production traffic, a huge
/// items_tags table) otherwise looks identical to a hung process: zero output between
/// "started the call" and "got a result", however long that takes.
///
/// The await genuinely parks while waiting, so a silent gap here is the database
/// taking its time and not a spinning process.
pub async fn db_wait<T, F>(label: &str, fut: F) -> T
where
    F: Future<Output = T>,
{
    tokio::pin!(fut);
    let start = Instant::now();
    let mut ticker = tokio::time::interval(Duration::from_secs(15));
    ticker.tick().await; // the first tick completes immediately

    loop {
        tokio::select! {
            v = &mut fut => return v,
            _ = ticker.tick() => {
                println!(
                    "  \u{b7} [{label}] still waiting on the database ({}s) — large/busy shared \
                     tables can genuinely take several minutes per page; not stuck",
                    start.elapsed().as_secs()
                );
            }
        }
    }
}

/// Make a label safe to embed in a filename (tenant ids are UUIDs; "root" in
/// dedicated mode).
pub fn sanitize_label(label: &str) -> String {
    label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn sanitize() {
        assert_eq!(super::sanitize_label("a-b_c.d"), "a-b_c.d");
        assert_eq!(super::sanitize_label("a/b c:d"), "a_b_c_d");
    }
}
