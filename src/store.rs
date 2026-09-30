//! Opening the wallet, resolving profiles, enumerating tenants, and preflight checks.

use anyhow::{Context, Result};
use aries_askar::entry::TagFilter;
use aries_askar::storage::backend::OrderBy;
use aries_askar::{ErrorKind, PassKey, Session, Store, StoreKeyMethod};

use crate::config::Config;
use crate::credo::category;
use crate::progress::db_wait;

/// Open the Askar store.
///
/// This is the entire "connect to the agent's wallet" step. Credo's `Agent.initialize()`
/// plus `AskarModule` plus `TenantsModule` collapse to one call, because everything
/// else those do is protocol machinery a purge never touches.
///
/// `profile: None` opens the store on its default profile (which Askar provisioned as
/// the wallet id); each scan and session below names its profile explicitly, exactly
/// as `AskarStoreManager.getInitializedStoreWithProfile` does.
pub async fn open(cfg: &Config) -> Result<Store> {
    let key_method = StoreKeyMethod::parse_uri(&cfg.key_derivation_method).with_context(|| {
        format!(
            "KEY_DERIVATION_METHOD={:?} is not a key method Askar recognises \
             (expected 'raw', 'kdf:argon2i:mod', 'kdf:argon2i:int' or 'none')",
            cfg.key_derivation_method
        )
    })?;

    let uri = cfg.store_uri();
    let pass_key = PassKey::from(cfg.wallet_key.as_str());

    let store = db_wait("store", Store::open(&uri, Some(key_method), pass_key, None))
        .await
        .map_err(|e| {
            let msg = e.to_string();
            // Askar's messages for the two most common misconfigurations are opaque,
            // and they are easy to confuse with each other. Name them explicitly.
            if msg.contains("key method mismatch") {
                // The store records its derivation method in config.key, and Askar
                // refuses to even try a different one. Credo defaults to
                // KdfMethod.Argon2IMod when keyDerivationMethod is unset, so a store
                // provisioned by an agent that never set it is NOT "raw" — despite
                // what the sample env files suggest.
                anyhow::anyhow!(
                    "KEY_DERIVATION_METHOD={:?} is not how this store was provisioned.\n\
                     Read the real method straight out of the store (it is not secret):\n\
                     \n    SELECT split_part(value, '?', 1) FROM config WHERE name='key';\n\
                     \n\
                     It returns e.g. 'kdf:argon2i:13:mod' -> use KEY_DERIVATION_METHOD=kdf:argon2i:mod,\n\
                     or 'raw' -> use KEY_DERIVATION_METHOD=raw.\n\
                     Note Credo defaults to kdf:argon2i:mod when keyDerivationMethod is unset.\n\
                     Underlying: {e}",
                    cfg.key_derivation_method
                )
            } else if e.kind() == ErrorKind::Encryption {
                anyhow::anyhow!(
                    "Askar rejected the store key. WALLET_KEY must match the agent's \
                     exactly (KEY_DERIVATION_METHOD={:?} was accepted, so it is the key \
                     itself that is wrong). Underlying: {e}",
                    cfg.key_derivation_method
                )
            } else {
                anyhow::anyhow!("Could not open the Askar store: {e}")
            }
        })?;

    Ok(store)
}

/// Enumerate every tenant registered in the wallet.
///
/// A TenantRecord lives in the ROOT profile and its Askar entry name is the tenant id,
/// so this needs no decryption at all — only `entry.name`.
pub async fn list_tenants(store: &Store) -> Result<Vec<String>> {
    let mut scan = db_wait(
        "root",
        store.scan(
            None, // root / default profile
            Some(category::TENANT.to_string()),
            None,
            None,
            None,
            Some(OrderBy::Id),
            false,
        ),
    )
    .await
    .context(
        "Cannot enumerate tenants: scanning the TenantRecord category failed. \
         Set TENANT_ALLOWLIST=id1,id2,... or TENANT_ID=<id> to target tenants explicitly.",
    )?;

    let mut ids = Vec::new();
    while let Some(batch) = scan.fetch_next().await? {
        for entry in batch {
            ids.push(entry.name);
        }
    }
    Ok(ids)
}

/// Cross-check that a profile actually exists before doing anything to it.
///
/// Askar reports a missing profile by erroring when a session is opened on it, which is
/// indistinguishable from a transport failure at the call site. Callers use this to get
/// a three-way outcome instead: exists, does not exist, or could not tell.
pub async fn profile_exists(store: &Store, profile: &str) -> Result<bool> {
    let profiles = store
        .list_profiles()
        .await
        .context("could not list store profiles")?;
    Ok(profiles.iter().any(|p| p == profile))
}

/// Count one category, returning `None` if the count itself failed.
///
/// A failing count is reported as unavailable rather than aborting the whole census —
/// one unreadable category should not cost the operator every other number.
pub async fn count_category(
    session: &mut Session,
    category: &str,
    tag_filter: Option<TagFilter>,
) -> Option<i64> {
    session.count(Some(category), tag_filter).await.ok()
}

/// Startup sanity check — the compensation for hardcoding category and state strings
/// rather than importing them from the agent framework.
///
/// Imported constants would turn an upstream rename into a compile error. Hardcoded
/// strings turn it into a silent zero instead, so we look for the shape of that
/// failure: if a wallet holds records under the
/// PROTECTED categories (connections and DIDs, which no purge ever removes) but every
/// purgeable category reads zero, the category names are far more likely to have
/// drifted than the tenant is to be genuinely empty. Say so loudly.
///
/// Returns `true` when the shape looks suspicious.
pub async fn preflight(session: &mut Session, label: &str) -> Result<bool> {
    let mut purgeable_total = 0i64;
    let mut protected_total = 0i64;

    for cat in category::PURGEABLE {
        purgeable_total += count_category(session, cat, None).await.unwrap_or(0);
    }
    for cat in category::PROTECTED {
        protected_total += count_category(session, cat, None).await.unwrap_or(0);
    }

    let suspicious = purgeable_total == 0 && protected_total > 0;
    if suspicious {
        eprintln!(
            "\u{26a0}\u{fe0f}  [{label}] PREFLIGHT: every purgeable category is empty, but the \
             protected categories hold {protected_total} records."
        );
        eprintln!(
            "    That usually means the Askar category names in credo.rs have drifted from the \
             Credo version the agent runs. Re-check the `.type` statics before trusting a \
             zero-result run. Expected categories: {:?}",
            category::PURGEABLE
        );
    }
    Ok(suspicious)
}
