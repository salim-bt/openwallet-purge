//! Read-only tenant sizing.
//!
//! Askar's `count()` is a server-side `SELECT COUNT(*)`, so this returns per-category
//! totals in milliseconds with no scan. Use it to rank tenants by size before a drain,
//! and to capture the before/after numbers around one.

use anyhow::Result;
use aries_askar::entry::TagFilter;
use aries_askar::Store;

use crate::config::Config;
use crate::credo::{
    category, credential_incomplete_states, proof_incomplete_states, tag, PROOF_STATES,
    TERMINAL_STATES,
};
use crate::store::count_category;

/// Thousands separators, en-US style.
pub fn fmt_count(n: Option<i64>) -> String {
    let Some(n) = n else {
        return "(unavailable)".to_string();
    };
    let neg = n < 0;
    let digits = n.abs().to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    if neg {
        format!("-{out}")
    } else {
        out
    }
}

struct CategoryRow {
    label: &'static str,
    key: &'static str,
}

const CATEGORIES: [CategoryRow; 8] = [
    CategoryRow { label: "Credentials        (CredentialRecord)", key: category::CREDENTIAL_EXCHANGE },
    CategoryRow { label: "Proofs             (ProofRecord)", key: category::PROOF_EXCHANGE },
    CategoryRow { label: "OOB                (OutOfBandRecord)", key: category::OUT_OF_BAND },
    CategoryRow { label: "DIDComm messages   (DidCommMessageRecord)", key: category::DIDCOMM_MESSAGE },
    CategoryRow { label: "Basic messages     (BasicMessageRecord)", key: category::BASIC_MESSAGE },
    CategoryRow { label: "Q&A                (QuestionAnswerRecord)", key: category::QUESTION_ANSWER },
    // Protected — NEVER purged. Counts must be IDENTICAL before vs after a drain.
    // This is the "did it leave what it must keep" check.
    CategoryRow { label: "Connections        (ConnectionRecord) [PROTECTED — must not change]", key: category::CONNECTION },
    CategoryRow { label: "DIDs               (DidRecord) [PROTECTED — must not change]", key: category::DID },
];

fn pad(s: &str, width: usize) -> String {
    let len = s.chars().count();
    if len >= width {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(width - len))
    }
}

pub async fn run(store: &Store, cfg: &Config, profile: Option<String>, label: &str) -> Result<()> {
    let mut session = store.session(profile).await?;

    println!("\n[{label}] Category totals:");

    // Sequential, with a line printed as each count lands — deliberately NOT
    // concurrent. Under DB contention one slow count used to make a concurrent
    // version print nothing until all eight finished, which is indistinguishable
    // from a hang (several minutes of silence after just the header was observed).
    // Each count is normally fast enough that sequential costs little, and a slow
    // one now only delays itself.
    for row in CATEGORIES {
        let total = count_category(&mut session, row.key, None).await;
        println!("  {} {}", pad(row.label, 50), fmt_count(total));
    }

    let groups: [(&str, &str, Vec<&str>); 2] = [
        (
            "Credentials",
            category::CREDENTIAL_EXCHANGE,
            credential_incomplete_states(),
        ),
        ("Proofs", category::PROOF_EXCHANGE, proof_incomplete_states()),
    ];

    for (group_label, key, incomplete) in groups {
        println!("\n  {group_label} — by state:");

        println!("    terminal (deleted by current purge when older than TTL):");
        let mut terminal_total = 0i64;
        for state in TERMINAL_STATES {
            let n = count_category(&mut session, key, Some(TagFilter::is_eq(tag::STATE, state))).await;
            if let Some(v) = n {
                if v > 0 {
                    terminal_total += v;
                }
            }
            println!("      {} {}", pad(state, 24), fmt_count(n));
        }
        println!(
            "      {} {}",
            pad("→ terminal subtotal", 24),
            fmt_count(Some(terminal_total))
        );

        println!("    incomplete (NOT purged today — stale-incomplete candidates):");
        let mut incomplete_total = 0i64;
        for state in &incomplete {
            let n = count_category(&mut session, key, Some(TagFilter::is_eq(tag::STATE, *state))).await;
            if let Some(v) = n {
                if v > 0 {
                    incomplete_total += v;
                }
            }
            println!("      {} {}", pad(state, 24), fmt_count(n));
        }
        println!(
            "      {} {}",
            pad("→ incomplete subtotal", 24),
            fmt_count(Some(incomplete_total))
        );

        // Credentials carry an extra warning: the incomplete subtotal above is
        // reportable volume, NOT a purge target.
        if key == category::CREDENTIAL_EXCHANGE && incomplete_total > 0 {
            println!(
                "      (credential incomplete records are never purged — a holder can still \
                 accept a pending offer after the stale TTL)"
            );
        }
        let _ = PROOF_STATES; // referenced for provenance; states come from credo.rs
    }

    if cfg.purge_stale_incomplete {
        println!(
            "\n  NOTE: PURGE_STALE_INCOMPLETE=true — a bulk-purge run would also delete the \
             proof incomplete states above, older than {} days.",
            cfg.stale_incomplete_ttl_days
        );
    }

    Ok(())
}
