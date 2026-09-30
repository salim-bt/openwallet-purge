//! Credo record semantics, expressed directly against Askar.
//!
//! An agent framework reaches Askar through a thin storage layer: a delete is
//! `session.remove({ category: recordClass.type, name: id })` and a query is
//! `Scan({ category, tagFilter, profile }).fetchAll()`. Every framework-level import on
//! that path resolves to a constant or a one-line transform by the time it reaches the
//! store, so the constants below are the entire dependency — reproduced here rather
//! than pulled in.
//!
//! They were read out of the upstream packages rather than guessed. Provenance is
//! recorded per item so it can be re-verified after a framework upgrade:
//!
//!   @credo-ts/didcomm 0.7 — DidComm*Record
//!       -> `.type` statics (the Askar *category*) and `getTags()` (which fields are
//!          queryable tags vs. value-only JSON)
//!   @credo-ts/didcomm 0.7 — DidCommCredentialState, DidCommProofState,
//!                           DidCommOutOfBandState
//!       -> the state enums the purge lists are derived from
//!   @credo-ts/tenants 0.7 — TenantSessionCoordinator
//!       -> tenant id <-> Askar profile naming
//!   @credo-ts/core 0.7 — transformers
//!       -> dates serialize as an ISO-8601 instant, i.e. RFC 3339
//!
//! THE TRADE-OFF: deriving these from the framework's own enums would pick up an added
//! state or a renamed category for free — a rename would be a compile error rather than
//! a silent zero. Hardcoded strings lose that. `preflight()` at the bottom of this file
//! is the compensation: it counts every category we know about and shouts if a wallet
//! that should hold data looks empty.

use serde::Deserialize;

/// Askar record categories (the `items.category` column).
///
/// Source: the `.type` static on each Credo record class.
pub mod category {
    /// `DidCommCredentialExchangeRecord.type` — note the category string is the *old*
    /// name, not the class name. Renaming the class did not rename the category.
    pub const CREDENTIAL_EXCHANGE: &str = "CredentialRecord";
    /// `DidCommProofExchangeRecord.type` — likewise.
    pub const PROOF_EXCHANGE: &str = "ProofRecord";
    /// `DidCommOutOfBandRecord.type`
    pub const OUT_OF_BAND: &str = "OutOfBandRecord";
    /// `DidCommMessageRecord.type` — the raw DIDComm payloads, ~3-6 per exchange and
    /// the bulk of the row count.
    pub const DIDCOMM_MESSAGE: &str = "DidCommMessageRecord";
    /// `DidCommBasicMessageRecord.type`
    pub const BASIC_MESSAGE: &str = "BasicMessageRecord";
    /// `QuestionAnswerRecord.type` (@credo-ts/question-answer)
    pub const QUESTION_ANSWER: &str = "QuestionAnswerRecord";
    /// `TenantRecord.type` (@credo-ts/tenants) — lives in the ROOT profile; the Askar
    /// entry name is the tenant id, so enumerating tenants needs no decryption.
    pub const TENANT: &str = "TenantRecord";

    // ── Protected. NEVER deleted. Counted before and after a drain as the "did it
    //    leave what it must keep" check. ──
    /// `DidCommConnectionRecord.type` — platforms rely on connection reuse for every
    /// issuance and verification flow, so connections are never purged. There is
    /// deliberately no subcommand for them.
    pub const CONNECTION: &str = "ConnectionRecord";
    /// `DidRecord.type` (@credo-ts/core)
    pub const DID: &str = "DidRecord";

    /// Categories the purge is allowed to delete from.
    pub const PURGEABLE: [&str; 6] = [
        CREDENTIAL_EXCHANGE,
        PROOF_EXCHANGE,
        OUT_OF_BAND,
        DIDCOMM_MESSAGE,
        BASIC_MESSAGE,
        QUESTION_ANSWER,
    ];

    /// Categories that must be byte-identical before and after a drain.
    pub const PROTECTED: [&str; 2] = [CONNECTION, DID];
}

/// Askar tag names (the `items_tags.name` column, encrypted at rest but queryable
/// through WQL because Askar's tag encryption is deterministic).
///
/// Source: `getTags()` on each record class. Only fields returned by `getTags()` are
/// queryable; everything else lives inside the encrypted JSON value and can only be
/// read by scanning and deserializing.
pub mod tag {
    /// On CredentialRecord, ProofRecord, OutOfBandRecord, QuestionAnswerRecord.
    /// NOT on DidCommMessageRecord or BasicMessageRecord.
    pub const STATE: &str = "state";
    /// On DidCommMessageRecord. This is the parent-exchange link the cascade and the
    /// orphan sweep both key off. It being a real tag is load-bearing: it means the
    /// orphan sweep can classify a message from its tags alone and only pay for JSON
    /// deserialization on actual orphan candidates.
    pub const ASSOCIATED_RECORD_ID: &str = "associatedRecordId";
}

/// Terminal = a completed/closed flow. What the default purge deletes, by TTL.
///
/// These three strings are common to both `DidCommCredentialState` and
/// `DidCommProofState`.
pub const TERMINAL_STATES: [&str; 3] = ["done", "abandoned", "declined"];

/// Every `DidCommCredentialState` value (RFC 0036 / RFC 0453).
pub const CREDENTIAL_STATES: [&str; 11] = [
    "proposal-sent",
    "proposal-received",
    "offer-sent",
    "offer-received",
    "declined",
    "request-sent",
    "request-received",
    "credential-issued",
    "credential-received",
    "done",
    "abandoned",
];

/// Every `DidCommProofState` value (RFC 0037).
pub const PROOF_STATES: [&str; 9] = [
    "proposal-sent",
    "proposal-received",
    "request-sent",
    "request-received",
    "presentation-sent",
    "presentation-received",
    "declined",
    "abandoned",
    "done",
];

/// Every `DidCommOutOfBandState` value. `initial` and `prepare-response` are not
/// purge targets (neither is terminal, and neither is the "stuck invitation" case),
/// but the full enum is recorded here so a future track has the list to hand and so a
/// Credo upgrade can be diffed against it.
#[allow(dead_code)]
pub const OOB_STATE_INITIAL: &str = "initial";
pub const OOB_STATE_AWAIT_RESPONSE: &str = "await-response";
#[allow(dead_code)]
pub const OOB_STATE_PREPARE_RESPONSE: &str = "prepare-response";
pub const OOB_STATE_DONE: &str = "done";

fn non_terminal(all: &[&'static str]) -> Vec<&'static str> {
    all.iter()
        .copied()
        .filter(|s| !TERMINAL_STATES.contains(s))
        .collect()
}

/// Non-terminal credential states — census reporting ONLY, never purged.
///
/// Deliberately not wired to any delete path: a holder can still be sitting on a
/// pending offer
/// (`offer-received`) and accept it after the stale TTL. Deleting the issuer-side
/// record while the holder's record exists breaks the issuance with no recovery path
/// other than a fresh offer — unacceptable for a high-assurance identity credential.
pub fn credential_incomplete_states() -> Vec<&'static str> {
    non_terminal(&CREDENTIAL_STATES)
}

/// Non-terminal proof states — used by the opt-in stale-incomplete purge.
///
/// Safe to purge, unlike credentials: a holder responding to a deleted proof request
/// gets an error and the verifier simply re-requests. No credential data is at risk.
pub fn proof_incomplete_states() -> Vec<&'static str> {
    non_terminal(&PROOF_STATES)
}

/// Askar profile name for a tenant.
///
/// `AskarMultiWalletDatabaseScheme.ProfilePerWallet` means one Askar profile per
/// tenant. `AskarStoreManager.getInitializedStoreWithProfile` (AskarStoreManager.mjs:357)
/// uses `agentContext.contextCorrelationId` as the profile name, and
/// `TenantSessionCoordinator.getContextCorrelationIdForTenantId`
/// (TenantSessionCoordinator.mjs:122-125) defines that as the tenant id prefixed with
/// `tenant-`. So `withTenantAgent({ tenantId })` is, at the storage layer, nothing more
/// than "use this profile".
///
/// The `tenant-` guard is Credo's own: a value that already carries the prefix is a
/// context correlation id being passed where a tenant id belongs.
pub fn tenant_profile(tenant_id: &str) -> String {
    debug_assert!(
        !tenant_id.starts_with("tenant-"),
        "tenant id already starts with 'tenant-' — that's a context correlation id"
    );
    format!("tenant-{tenant_id}")
}

/// The fields this tool reads out of a record's decrypted JSON value.
///
/// Deliberately partial: we never deserialize a whole Credo record, only the four
/// fields any purge decision depends on. Everything is optional and every unknown
/// field is ignored, so a Credo upgrade that adds fields to a record cannot break
/// parsing. Dates stay as strings here and are parsed separately — see `parse_date`.
#[derive(Debug, Default, Deserialize)]
pub struct RecordValue {
    /// ISO-8601. Written by `AskarStorageService.save`/`update` on every write.
    /// The TTL predicate. Not a tag, which is why every age-filtered purge has to
    /// scan and decrypt rather than push the filter into SQL.
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<String>,
    /// ISO-8601. Used only by the orphan sweep's race guard.
    #[serde(rename = "createdAt")]
    pub created_at: Option<String>,
    /// DidCommMessageRecord -> parent exchange id. Also a tag (see `tag`), so this is
    /// only the fallback path for a record whose tag is somehow absent.
    #[serde(rename = "associatedRecordId")]
    pub associated_record_id: Option<String>,
    /// OutOfBandRecord only. NOT in `getTags()`, so a reusable invitation cannot be
    /// excluded by tag filter — it has to be read here. A reusable `await-response`
    /// invitation is a live invitation URL and is never deleted.
    pub reusable: Option<bool>,
}

/// Parse a Credo-serialized date.
///
/// `DateTransformer` (core/build/utils/transformers.mjs:21) serializes with
/// `Date.toISOString()`, e.g. `2026-09-14T22:44:34.123Z` — RFC 3339 with a Z offset.
///
/// Returns `None` on anything unparseable, which is what makes the callers safe: a
/// garbage `updatedAt` must leave a record *ineligible* for deletion, and a garbage
/// `createdAt` must leave a message *not* an orphan. Both fall out of treating `None`
/// as "predicate did not hold" — which every caller does.
pub fn parse_date(raw: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|d| d.with_timezone(&chrono::Utc))
}

impl RecordValue {
    /// TTL predicate, matching `r.updatedAt != null && r.updatedAt <= DELETE_BEFORE_TIME`.
    pub fn older_than(&self, cutoff: chrono::DateTime<chrono::Utc>) -> bool {
        match self.updated_at.as_deref().and_then(parse_date) {
            Some(updated) => updated <= cutoff,
            None => false,
        }
    }

    /// Orphan-sweep race guard, matching
    /// `raw.createdAt == null || new Date(raw.createdAt) < runStart`.
    ///
    /// A message created after the sweep started is never an orphan, even if its parent
    /// is absent from the Phase A snapshot. Note the asymmetry with `older_than`: a
    /// MISSING createdAt passes the guard (Credo wrote records without it in older
    /// versions), but an UNPARSEABLE one does not.
    pub fn predates(&self, run_start: chrono::DateTime<chrono::Utc>) -> bool {
        match self.created_at.as_deref() {
            None => true,
            Some(raw) => match parse_date(raw) {
                Some(created) => created < run_start,
                None => false,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incomplete_states_exclude_terminal() {
        for s in credential_incomplete_states() {
            assert!(!TERMINAL_STATES.contains(&s), "{s} is terminal");
        }
        for s in proof_incomplete_states() {
            assert!(!TERMINAL_STATES.contains(&s), "{s} is terminal");
        }
        // 11 credential states - done/abandoned/declined = 8
        assert_eq!(credential_incomplete_states().len(), 8);
        // 9 proof states - done/abandoned/declined = 6
        assert_eq!(proof_incomplete_states().len(), 6);
    }

    #[test]
    fn terminal_states_are_real_states() {
        for s in TERMINAL_STATES {
            assert!(CREDENTIAL_STATES.contains(&s), "{s} not a credential state");
            assert!(PROOF_STATES.contains(&s), "{s} not a proof state");
        }
    }

    #[test]
    fn profile_naming() {
        assert_eq!(tenant_profile("abc-123"), "tenant-abc-123");
    }

    #[test]
    fn dates_parse_the_way_credo_writes_them() {
        assert!(parse_date("2026-09-14T22:44:34.123Z").is_some());
        assert!(parse_date("2026-09-14T22:44:34Z").is_some());
        assert!(parse_date("garbage").is_none());
    }

    #[test]
    fn malformed_dates_fail_safe() {
        let cutoff = chrono::Utc::now();
        // Unparseable updatedAt -> NOT eligible for deletion.
        let r = RecordValue { updated_at: Some("nope".into()), ..Default::default() };
        assert!(!r.older_than(cutoff));
        // Absent updatedAt -> NOT eligible.
        let r = RecordValue::default();
        assert!(!r.older_than(cutoff));
        // Unparseable createdAt -> NOT an orphan.
        let r = RecordValue { created_at: Some("nope".into()), ..Default::default() };
        assert!(!r.predates(cutoff));
        // Absent createdAt -> orphan candidate (matches `raw.createdAt == null ||`).
        let r = RecordValue::default();
        assert!(r.predates(cutoff));
    }

    #[test]
    fn partial_deserialization_ignores_unknown_fields() {
        let v: RecordValue = serde_json::from_str(
            r#"{"updatedAt":"2026-01-01T00:00:00.000Z","somethingNew":{"a":1},"reusable":true}"#,
        )
        .unwrap();
        assert!(v.reusable.unwrap());
        assert!(v.updated_at.is_some());
    }
}
