# openwallet-purge

Askar wallet pruning for multi-tenant SSI platforms — a single static binary with no
runtime dependencies.

It connects straight to the Askar/PostgreSQL wallet store and deletes stale exchange
records without touching the running agent controller.

---

## Why this needs no agent framework

The wallet is an [Askar](https://github.com/openwallet-foundation/askar) store, and this
binary links `aries-askar` directly. Credo's `AskarStorageService` is a thin pass-through
over the same library — `deleteById` is a `session.remove({ category, name })`, and
`findByQuery` is a `Scan({ category, tagFilter, profile }).fetchAll()` — so talking to
Askar directly loses nothing on the delete path.

What remains of the framework dependency is a set of constants: category strings, state
values, and the tenant-to-profile naming rule. Those live in
[`src/credo.rs`](src/credo.rs), each recorded with the upstream package and version it
was read from.

**The reason this is safe: the tool only ever deletes.** It never writes a record, so the
serialization and tag-transform logic — the only part of the storage layer with real
behaviour — is never reached.

---

## Build

```sh
cargo build --release          # -> target/release/credo-purge  (~3.4 MB)
```

Only system libraries are dynamically linked (no OpenSSL — TLS is rustls, compiled in).
Copy the one file to the host and run it.

**Building for the Linux EC2 host from macOS** — either build on the host itself
(`cargo` + a git checkout) or cross-compile.

Mind the architecture — check the target host rather than assuming. Graviton
instances are `aarch64`; Intel/AMD ones are `x86_64`. `uname -m` on the host settles
it.

```sh
cargo install cross
cross build --release --target aarch64-unknown-linux-gnu   # Graviton hosts
cross build --release --target x86_64-unknown-linux-gnu    # Intel/AMD hosts
```

Note `Cargo.toml` pins Askar to an exact **git tag**, so the first build needs network
access to GitHub. Currently `v0.4.6`. Both `0.4.6` and `0.5.0` were verified to produce
byte-identical purge results on a real wallet — same surviving rows, same tags — and
the API surface used here is unchanged between them, so either is fine. `0.4.6` is also
on crates.io, so at that version the git dependency can be replaced with a plain
`version = "0.4.6"` if you would rather not reach GitHub at build time.

**CI builds** — `.github/workflows/release.yml` cross-compiles both Linux targets and
attaches them to a GitHub Release. Pushing a `v*` tag builds both architectures;
running the workflow by hand lets you pick one, and publishes only if you name a tag
(otherwise the binaries are left as a workflow artifact). It uses `cross` rather than
the runner's own toolchain on purpose: the runner links against glibc 2.39, which
would not start on Amazon Linux 2023 (glibc 2.34). The build log prints the binary's
glibc floor so a mismatch shows up there rather than on the host.

On a private repo the release assets need an authenticated download — a plain `curl` of
the browser URL returns HTML, not the binary. Run this from a checkout, or pass
`-R <owner>/<repo>`:

```sh
gh release download v0.1.0 -p 'credo-purge-linux-aarch64*'
sha256sum -c credo-purge-linux-aarch64.sha256
chmod +x credo-purge-linux-aarch64
```

---

## Commands

| Command | What it does |
|---|---|
| `credo-purge census` | Read-only per-category record counts |
| `credo-purge purge` | Full drain: all categories, all targets, with checkpoint/resume |
| `credo-purge bulk-purge` | Fast parent-only purge, no child cascade |
| `credo-purge orphan-sweep` | DidComm messages whose parent exchange is gone |
| `credo-purge credentials` | Terminal credential exchanges + their message children |
| `credo-purge proofs` | Terminal proof exchanges + their message children |
| `credo-purge oob` | Out-of-band invitations |
| `credo-purge basic-messages` | Basic messages |
| `credo-purge question-answer` | Question-answer records |
| `credo-purge tenants` | List tenant ids |

Every setting is an environment variable with a fail-safe default; see
[`.env.example`](.env.example).

`ConnectionRecord` is never deleted and there is deliberately no subcommand for it.

### Multi-tenant mode is blocked

`PURGE_MODE=multi-tenant` is refused at startup, before the store is opened. Only the
dedicated agent is drained at present.

The multi-tenant logic is **left in place and unmodified** — tenant enumeration via the
`TenantRecord` category, `tenant-<id>` profile naming, per-tenant iteration,
checkpoint/resume, the not-found skip. It is simply unreachable. Re-enable by flipping
`MULTI_TENANT_ENABLED` in `src/config.rs`.

It is a compile-time constant rather than an env var deliberately: an env var is a
toggle, not a block, and re-enabling should be a decision visible in a diff — not
something a stray variable in a cron environment can do by accident.

The default `PURGE_MODE` stays `multi-tenant`, which looks odd but is the fail-safe
choice: an **unset** `PURGE_MODE` then hits the block and errors, instead of silently
draining the root profile as though it were the dedicated agent. `PURGE_MODE=dedicated`
must be stated explicitly.

Before re-enabling, re-run the validation in *Rolling it out*. That path has never been exercised
against a real multi-tenant store — the only wallet tested has one profile — and both
traps found on the dedicated agent (`KEY_DERIVATION_METHOD` not being `raw`, `DB_USER`
determining the schema) would break a multi-tenant run silently.

### Safety gates

- `DRY_RUN` defaults to dry-run. **Only** the literal `DRY_RUN=false` deletes.
- `bulk-purge` additionally requires `BULK_CONFIRM=true`, checked before the store is
  even opened.
- Stale-incomplete purge needs `PURGE_STALE_INCOMPLETE=true`, applies to **proofs
  only**, and uses a separate, more conservative TTL. A 0-day floor needs a second key
  (`STALE_ALLOW_ZERO_TTL=true`).

---

## CSV audit trail

Every purge appends to `AUDIT_CSV` (default `./logs/purge-audit.csv`), **one row per
target, flushed as that target finishes** — not buffered to the end. A 29-tenant drain
that dies on tenant 20 leaves 19 durable rows plus a `failed` row for the one that
broke. Parent directories are created automatically. `--no-audit` turns it off.

```
started_at,finished_at,duration_s,command,status,mode,purge_mode,target,wallet_id,
ttl_days,stale_incomplete_ttl_days,purge_stale_incomplete,throttle_ms,heartbeat_every,
bulk_purge_batch_size,orphan_scan_batch_size,orphan_delete_batch_size,db_max_connections,
server_side_delete,
credentials_parents,credentials_children,proofs_parents,proofs_children,oob_records,
orphans_deleted,basic_messages,question_answers,total_records,error
```

```csv
2026-09-29T22:10:04+00:00,2026-09-29T22:11:31+00:00,87,purge,ok,live,dedicated,root,<wallet-id>,30,,false,250,20,500,2000,500,50,false,412,1236,88,264,17,3390,0,2,5409,
2026-09-29T22:11:31+00:00,2026-09-29T22:11:33+00:00,2,purge,failed,live,dedicated,root,<wallet-id>,30,,false,250,20,500,2000,500,50,false,0,0,0,0,0,0,0,0,0,"db timeout, retrying"
```

Notes on reading it:

- **Parameters are denormalised onto every row on purpose.** A row has to be
  interpretable on its own months later, without cross-referencing shell history.
- **`status`** is `ok`, `failed`, or `skipped` (target named but no Askar profile
  exists). Failures get a row rather than a gap — a gap is indistinguishable from
  "never attempted".
- **`total_records`** counts parents *and* cascaded children, so it should track the
  actual drop in wallet row count.
- **`mode`** is `dry-run` or `live`. Dry-run rows record what *would* have gone.
- **A multi-tenant run writes no grand-total row** — the per-tenant rows sum to it, and
  a total row would double-count any `SUM()` over the column.
- Rows are audited *before* the checkpoint is written. If the process dies between the
  two, the tenant is re-purged next run (deletes are already-gone tolerant) and the CSV
  shows both attempts. The reverse order could checkpoint a tenant with no record it ran.
- `census` writes nothing — the file is a record of deletions.

Quick queries:

```sh
# What did we delete last night, by tenant?
awk -F, '$1 ~ /^2026-09-28/ && $5=="ok" {print $8, $28}' logs/purge-audit.csv

# Anything fail this month?
grep ',failed,' logs/purge-audit.csv
```

---

## Design notes

- **Scans stream.** Askar's `Scan` is a `Stream` and each page drops when it leaves
  scope, so memory stays flat across a whole scan regardless of wallet size. There is no
  per-batch buffer to free and no heap ceiling to raise.
- **A delete batch is one transaction** — N statements, one commit, one fsync — rather
  than N autocommitting deletes competing for `DB_MAX_CONNECTIONS`.
- **The cascade child lookup is one query per batch.** `associatedRecordId` is a real
  Askar tag, so a batch of 100 parents resolves in a single `any_of` filter instead of
  100 round trips.
- **The orphan sweep deserializes JSON only for orphan candidates.** It reads the parent
  link off `entry.tags` and pays for `serde_json` only when a record actually looks
  orphaned, which is a small fraction of what it scans.
- **Scans pass `OrderBy::Id`.** Paging across separate scan calls is only stable with an
  explicit sort; without one, a resumed scan can silently return short counts rather
  than erroring.

**Opt-in: `--server-side-delete`.** Collapses a track into a single server-side
`DELETE ... WHERE`. It only applies where the whole `(category, state)` set is eligible,
i.e. **`TTL_DAYS=0`**, and never to the non-reusable OOB track. An age filter reads
`updatedAt`, which lives inside the encrypted record value rather than in a tag, so it
cannot be pushed into SQL. With any `TTL_DAYS > 0` the flag is ignored.

---

## Category drift, and the guard against it

Category and state strings are hardcoded in [`src/credo.rs`](src/credo.rs) rather than
imported from the agent framework. That buys the zero-dependency binary, but it means an
upstream rename cannot surface as a compile error — it would surface as a category that
silently matches nothing.

`store::preflight` is the guard: if a wallet holds records under the **protected**
categories (`ConnectionRecord`, `DidRecord` — never purged) but every purgeable category
reads zero, that is far more likely to be category drift than a genuinely empty target,
and it says so loudly rather than reporting a clean run.

After any framework upgrade on the agent, re-check the `.type` statics against
`src/credo.rs`, which records the upstream package and version each one came from.

---

## Host notes: the dedicated agent

`PURGE_MODE=dedicated` targets a single-profile Askar store. On this platform that
store is **not RDS** — it is a `postgres:16` container running on the agent host, with
its data on a bind mount. Confirm the specifics for your deployment; they differ from
the multi-tenant defaults in `.env.example`:

| | multi-tenant (RDS) | dedicated (containerised) |
|---|---|---|
| `DB_HOST` | the RDS endpoint | the agent host, or `localhost` on-box |
| `DB_PORT` | `5432` | often **non-default** — check the published port |
| `DB_USER` | `postgres` | the user the agent connects as — **see below** |
| `PURGE_MODE` | `multi-tenant` | `dedicated` |

Three things to establish per wallet before a first run, each of which fails in a way
that does not look like a configuration problem:

**1. The key derivation method is often not `raw`.** Credo defaults to
`KdfMethod.Argon2IMod` whenever the agent never sets `keyDerivationMethod`, and Askar
refuses to open a store with the wrong method rather than degrading. Read the real
value out of the store — it is not secret:

```sql
SELECT split_part(value, '?', 1) FROM config WHERE name = 'key';
-- 'kdf:argon2i:13:mod' -> KEY_DERIVATION_METHOD=kdf:argon2i:mod
-- 'raw'                -> KEY_DERIVATION_METHOD=raw
```

**2. Set `DB_SCHEMA` — otherwise `DB_USER` silently decides where the store is.**
Askar creates its tables in `schema.unwrap_or(username)` at provision time and locates
them again through `CURRENT_SCHEMAS(false)` — the Postgres `search_path`, default
`"$user", public`. Credo never sets the `schema` URI parameter, so a Credo-provisioned
store lives in a schema named after whichever user the agent connects as, and
connecting as anyone else reports **no store** in a perfectly good database:

```
DB_USER=postgres, no DB_SCHEMA   ->  relation "config" does not exist
DB_USER=postgres, DB_SCHEMA set  ->  store opens normally
```

Askar applies `DB_SCHEMA` as `search_path` on every pooled connection, so setting it
pins where the store is and reduces `DB_USER` to authentication. Find the value with:

```sql
SELECT table_schema FROM information_schema.tables
WHERE table_name IN ('config','profiles','items','items_tags')
GROUP BY table_schema HAVING count(*) >= 3;
```

This does diverge from how the agent opens the store, so the value must be right —
read it per wallet rather than assuming.

**3. Disk is often shared.** A containerised wallet typically sits on the host's root
volume alongside every other service on that box. A large purge's WAL growth and
post-vacuum bloat land on that shared volume, so watch free space rather than assuming
RDS-style isolation.

Also confirm which **Credo framework** version the agent image corresponds to before
trusting the hardcoded category names in `src/credo.rs` — they were read from Credo
0.7. `store::preflight` catches a mismatch, but checking first is cheaper.

See [`testing/`](testing/) for cloning a wallet locally to test against.

## Rolling it out

Validation is a counting exercise — establish the numbers, then delete.

1. `credo-purge census` against a target. Record every category total and per-state
   count as the baseline.
2. `DRY_RUN=true credo-purge bulk-purge`, then `DRY_RUN=true credo-purge purge` on one
   small target. Eligible counts per track should be consistent with the census.
3. Go live on that one small target, with a census before and after. The **protected**
   category counts must be unchanged, and `total_records` in the CSV should equal the
   drop in the purgeable totals.
4. Work up to the largest target last.

```sh
cargo test        # 20 tests: category/state constant invariants, fail-safe TTL
                  # resolution, store-URI encoding, CSV escaping and appending,
                  # and that multi-tenant stays blocked while dedicated does not
```

## Validated against a production-scale wallet

The full drain sequence (terminal bulk-purge → orphan sweep → stale-incomplete → orphan
sweep → basic/Q&A, at `TTL_DAYS=20`) was run against a local clone of a real
single-profile wallet holding 71,379 items.

The result was checked by fingerprinting the database rather than by trusting the
reported counts — md5 over all surviving record ids, over the category distribution, and
over the full `items_tags` contents. The protected categories came through untouched:
`ConnectionRecord` (2,802) and `DidRecord` (5,612), exactly as before the run. The whole
sequence took 29s, about 11s of which was `THROTTLE_MS` sleeps.

See [`testing/`](testing/) to reproduce.
