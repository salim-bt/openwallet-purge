//! `env-apply` — bring an existing agent `.env` in line with a values file.
//!
//! Unrelated to the wallet: this edits a dotenv file on the host, nothing else. It is
//! generic on purpose — the values themselves are supplied at run time (a file, or
//! stdin) and never live in this repo.
//!
//! Each key in the values file is updated in place where the `.env` already has it and
//! appended where it does not. Every other line — comments, ordering, keys the values
//! file does not mention — is left byte-for-byte alone.
//!
//! Values file syntax is dotenv (`KEY=value`, `#` comments, optional `export `), plus
//! three directives in the value position:
//!
//! - `@prompt`         ask on the terminal; blank keeps the current value if there is one
//! - `@prompt-url`     as `@prompt`, but must be http(s) and a trailing `/` is stripped
//! - `@random-hex:N`   N random bytes, hex-encoded — ONLY when the key is missing or
//!                     empty. An existing value is never regenerated: rotating a key
//!                     that clients already hold would lock them out.
//!
//! A literal value that starts with `@` is written `@@...`.
//!
//! When a literal value would replace a different, non-empty one already in the file,
//! both are shown and the runner is asked before it is changed — default yes, `n`
//! keeps the current value; `--yes` skips the question.
//! Prompted keys show their current value in the prompt instead, so typing a new value
//! is the decision. Keys that look secret (see `SECRET_HINTS`) are shown masked.
//!
//! `--review-json` prints a JSON file (e.g. the agent's own config) before the prompts,
//! so whoever runs it can check the box before typing anything. Fields whose name looks
//! secret (key, password, secret, token, seed, private, mnemonic) are masked.

use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
enum Directive {
    Literal(String),
    Prompt,
    PromptUrl,
    RandomHex(usize),
}

#[derive(Debug, PartialEq)]
enum Resolved {
    Set(String),
    Keep,
    Declined,
}

#[derive(Debug, PartialEq)]
enum Status {
    Added,
    Updated,
    Unchanged,
    Kept,
    Declined,
}

pub struct Args<'a> {
    pub values: &'a str,
    pub env: Option<&'a Path>,
    pub set: &'a [String],
    pub dry_run: bool,
    /// Accept every update of an existing value without asking.
    pub yes: bool,
    /// None: no review. Some(None): ask for the path. Some(Some(p)): print p.
    pub review_json: Option<Option<&'a Path>>,
}

pub fn run(args: Args) -> Result<()> {
    let values_src = if args.values == "-" {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s).context("reading values from stdin")?;
        s
    } else {
        std::fs::read_to_string(args.values)
            .with_context(|| format!("reading values file {}", args.values))?
    };
    let mut entries = parse_values(&values_src)?;

    // --set KEY=VALUE answers a prompt non-interactively, or overrides/adds a key.
    let mut overrides = HashMap::new();
    for s in args.set {
        let (k, v) = s
            .split_once('=')
            .with_context(|| format!("--set {s:?}: expected KEY=VALUE"))?;
        let k = k.trim();
        check_key(k)?;
        if !entries.iter().any(|(key, _)| key == k) {
            entries.push((k.to_string(), Directive::Literal(String::new())));
        }
        overrides.insert(k.to_string(), v.to_string());
    }

    let mut tty = None;

    // Resolve the real file, so a symlinked .env is edited rather than replaced.
    let env_path = existing_file(
        &mut tty,
        args.env,
        ("the .env path", "--env <path>", "Path to the agent's existing .env: "),
    )
    .context("env-apply only edits an existing file")?;
    let original = std::fs::read_to_string(&env_path)
        .with_context(|| format!("reading {}", env_path.display()))?;
    let lines: Vec<String> = original.lines().map(str::to_string).collect();
    let current = current_values(&lines);

    println!("\nowpurge  —  env-apply");
    println!("Target  : {}", env_path.display());

    if let Some(given) = args.review_json {
        let path = existing_file(
            &mut tty,
            given,
            ("the review file path", "--review-json <path>", "Path to the agent's config JSON to review: "),
        )?;
        let raw = std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        let mut json: serde_json::Value =
            serde_json::from_str(&raw).with_context(|| format!("{} is not valid JSON", path.display()))?;
        mask_secrets(&mut json);
        println!("\n── {} (secrets masked) ──", path.display());
        println!("{}", serde_json::to_string_pretty(&json)?);
        println!("──\n");
    }

    let mut resolved = Vec::new();
    for (key, directive) in &entries {
        let cur = current.get(key).map(String::as_str);
        let r = match overrides.get(key) {
            Some(v) => match directive {
                Directive::PromptUrl => Resolved::Set(normalize_url(key, v)?),
                _ => Resolved::Set(v.clone()),
            },
            None => resolve(key, directive, cur, &mut |prompt| ask(&mut tty, key, &format!("--set {key}=..."), prompt))?,
        };
        resolved.push((key.clone(), r));
    }

    // Replacing an existing value with a literal from the values file needs the runner's
    // say-so. --set and prompted values were already chosen by the runner, so they don't.
    for ((key, r), (_, directive)) in resolved.iter_mut().zip(&entries) {
        let Resolved::Set(new) = r else { continue };
        if overrides.contains_key(key) || matches!(directive, Directive::Prompt | Directive::PromptUrl) {
            continue;
        }
        let Some(old) = existing_differs(&lines, key, new) else { continue };
        println!("\n{key} is already set:");
        println!("  current: {}", shown(key, &old));
        println!("  new    : {}", shown(key, new));
        if args.dry_run || args.yes {
            continue;
        }
        let answer = ask(&mut tty, key, "--yes, or --set KEY=VALUE per key", "Update it? [Y/n]: ")?;
        if matches!(answer.trim().to_ascii_lowercase().as_str(), "n" | "no") {
            *r = Resolved::Declined;
        }
    }

    let (out, report) = apply(&lines, &resolved)?;

    println!();
    for (key, status) in &report {
        let s = match status {
            Status::Added => "added",
            Status::Updated => "updated",
            Status::Unchanged => "unchanged",
            Status::Kept => "kept (existing value)",
            Status::Declined => "left as is (update declined)",
        };
        println!("  {key:<45} {s}");
    }
    let changed = report.iter().any(|(_, s)| matches!(s, Status::Added | Status::Updated));

    if !changed {
        println!("\nNothing to change.");
        return Ok(());
    }
    if args.dry_run {
        println!("\nDry run — {} not modified.", env_path.display());
        return Ok(());
    }

    let backup = write_with_backup(&env_path, &out)?;
    println!("\nWrote {}  (backup: {})", env_path.display(), backup.display());
    println!("Restart the agent for the new values to take effect.");
    Ok(())
}

fn check_key(k: &str) -> Result<()> {
    let mut chars = k.chars();
    let ok = matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !ok {
        bail!("{k:?} is not a valid env var name");
    }
    Ok(())
}

/// Split a dotenv line into (key, raw value), or None for comments/blank/other lines.
fn split_line(line: &str) -> Option<(&str, &str)> {
    let t = line.trim_start();
    let t = t.strip_prefix("export ").unwrap_or(t);
    let (k, v) = t.split_once('=')?;
    let k = k.trim();
    check_key(k).ok()?;
    Some((k, v))
}

fn unquote(v: &str) -> String {
    let v = v.trim();
    for q in ['"', '\''] {
        if v.len() >= 2 && v.starts_with(q) && v.ends_with(q) {
            return v[1..v.len() - 1].to_string();
        }
    }
    // Unquoted: a ` #` starts an inline comment, as the Node dotenv parser treats it.
    match v.find(" #") {
        Some(i) => v[..i].trim_end().to_string(),
        None => v.to_string(),
    }
}

fn parse_values(src: &str) -> Result<Vec<(String, Directive)>> {
    let mut out: Vec<(String, Directive)> = Vec::new();
    for (n, line) in src.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let Some((k, v)) = split_line(t) else {
            bail!("values line {}: expected KEY=value", n + 1);
        };
        let v = unquote(v);
        let d = if let Some(rest) = v.strip_prefix("@@") {
            Directive::Literal(format!("@{rest}"))
        } else if v == "@prompt" {
            Directive::Prompt
        } else if v == "@prompt-url" {
            Directive::PromptUrl
        } else if let Some(n_bytes) = v.strip_prefix("@random-hex:") {
            let n_bytes: usize = n_bytes
                .parse()
                .ok()
                .filter(|n| (1..=1024).contains(n))
                .with_context(|| format!("{k}: @random-hex needs a byte count 1..=1024"))?;
            Directive::RandomHex(n_bytes)
        } else if v.starts_with('@') {
            bail!("{k}: unknown directive {v:?} (write @@ for a literal leading @)");
        } else {
            Directive::Literal(v)
        };
        match out.iter().find(|(key, _)| key == k) {
            Some((_, prev)) if *prev == d => {} // repeated with the same value: harmless
            Some(_) => bail!("{k} appears twice in the values file with different values"),
            None => out.push((k.to_string(), d)),
        }
    }
    Ok(out)
}

/// Current value per key. Where a key repeats, the last one wins, as in Node's dotenv.
fn current_values(lines: &[String]) -> HashMap<String, String> {
    lines
        .iter()
        .filter_map(|l| split_line(l))
        .map(|(k, v)| (k.to_string(), unquote(v)))
        .collect()
}

/// The value an update would replace, when it is non-empty and differs from `new`.
/// Filling an empty or missing key is not a replacement and needs no confirmation.
fn existing_differs(lines: &[String], key: &str, new: &str) -> Option<String> {
    lines
        .iter()
        .filter_map(|l| split_line(l))
        .filter(|(k, _)| *k == key)
        .map(|(_, v)| unquote(v))
        .filter(|v| !v.is_empty() && v != new)
        .last()
}

/// A value as shown to the runner: masked when the key looks secret.
fn shown(key: &str, v: &str) -> String {
    if v.is_empty() {
        return "(empty)".into();
    }
    let lk = key.to_ascii_lowercase();
    if !SECRET_HINTS.iter().any(|h| lk.contains(h)) {
        return v.to_string();
    }
    let n = v.chars().count();
    if n >= 12 {
        format!("********{}", v.chars().skip(n - 4).collect::<String>())
    } else {
        "********".into()
    }
}

fn normalize_url(key: &str, v: &str) -> Result<String> {
    let v = v.trim().trim_end_matches('/');
    if !(v.starts_with("https://") || v.starts_with("http://")) || v.contains(char::is_whitespace) {
        bail!("{key}: {v:?} is not an http(s) URL");
    }
    Ok(v.to_string())
}

fn resolve(
    key: &str,
    d: &Directive,
    current: Option<&str>,
    ask: &mut dyn FnMut(&str) -> Result<String>,
) -> Result<Resolved> {
    let has_current = current.is_some_and(|c| !c.is_empty());
    let hint = match current {
        Some(c) if !c.is_empty() => format!(" (current: {}) [blank keeps it]", shown(key, c)),
        _ => String::new(),
    };
    Ok(match d {
        Directive::Literal(v) => Resolved::Set(v.clone()),
        Directive::RandomHex(_) if has_current => Resolved::Keep,
        Directive::RandomHex(n) => Resolved::Set(random_hex(*n)?),
        Directive::Prompt | Directive::PromptUrl => loop {
            let answer = ask(&format!("{key}{hint}: "))?;
            let answer = answer.trim();
            if answer.is_empty() {
                if has_current {
                    break Resolved::Keep;
                }
                continue;
            }
            if *d == Directive::Prompt {
                break Resolved::Set(answer.to_string());
            }
            match normalize_url(key, answer) {
                Ok(u) => break Resolved::Set(u),
                Err(e) => eprintln!("  {e}"),
            }
        },
    })
}

/// The terminal, opened once. The reader is kept for the whole run: a fresh BufReader
/// per prompt would read ahead and swallow answers typed or pasted for later prompts.
type Tty = std::io::BufReader<std::fs::File>;

/// Prompts go to the terminal, not stdin, so values can be piped in on stdin.
fn ask(tty: &mut Option<Tty>, what: &str, flag: &str, prompt: &str) -> Result<String> {
    if tty.is_none() {
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .map_err(|_| {
                anyhow::anyhow!(
                    "{what} is needed but there is no terminal to prompt on — pass {flag}"
                )
            })?;
        *tty = Some(std::io::BufReader::new(f));
    }
    let r = tty.as_mut().unwrap();
    r.get_mut().write_all(prompt.as_bytes())?;
    r.get_mut().flush()?;
    let mut line = String::new();
    if r.read_line(&mut line)? == 0 {
        bail!("{what}: terminal closed before an answer was given");
    }
    Ok(line)
}

/// The given path, or one asked for on the terminal until it names an existing file.
/// Canonicalized, so a symlink is followed rather than replaced.
fn existing_file(
    tty: &mut Option<Tty>,
    given: Option<&Path>,
    (what, flag, prompt): (&str, &str, &str),
) -> Result<PathBuf> {
    if let Some(p) = given {
        return std::fs::canonicalize(p).with_context(|| format!("{} not found", p.display()));
    }
    loop {
        let p = expand_home(ask(tty, what, flag, prompt)?.trim());
        if p.as_os_str().is_empty() {
            continue;
        }
        match std::fs::canonicalize(&p) {
            Ok(p) if p.is_file() => return Ok(p),
            _ => eprintln!("  {} is not an existing file", p.display()),
        }
    }
}

const SECRET_HINTS: &[&str] = &["key", "password", "secret", "token", "seed", "private", "mnemonic"];

/// Mask every non-empty string or number under a field whose name looks secret.
/// Empty values stay visible, so a reviewer can tell "unset" from "set".
fn mask_secrets(v: &mut serde_json::Value) {
    use serde_json::Value;
    match v {
        Value::Object(map) => {
            for (k, child) in map.iter_mut() {
                let lk = k.to_ascii_lowercase();
                if SECRET_HINTS.iter().any(|h| lk.contains(h)) {
                    mask_all(child);
                } else {
                    mask_secrets(child);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(mask_secrets),
        _ => {}
    }
}

fn mask_all(v: &mut serde_json::Value) {
    use serde_json::Value;
    match v {
        Value::String(s) if s.is_empty() => {}
        Value::String(_) | Value::Number(_) => *v = Value::String("********".into()),
        Value::Object(map) => map.values_mut().for_each(mask_all),
        Value::Array(items) => items.iter_mut().for_each(mask_all),
        _ => {}
    }
}

fn expand_home(p: &str) -> PathBuf {
    match (p.strip_prefix("~/"), std::env::var_os("HOME")) {
        (Some(rest), Some(home)) => PathBuf::from(home).join(rest),
        _ => PathBuf::from(p),
    }
}

fn random_hex(n: usize) -> Result<String> {
    let mut buf = vec![0u8; n];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .context("reading /dev/urandom")?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// Render a value so the Node dotenv parser reads it back unchanged.
fn format_value(key: &str, v: &str) -> Result<String> {
    if v.contains('\n') || v.contains('\r') {
        bail!("{key}: multi-line values are not supported");
    }
    let plain = !v.is_empty()
        && !v.chars().any(|c| c.is_whitespace() || matches!(c, '#' | '"' | '\'' | '`' | '\\' | '$'));
    if plain || v.is_empty() {
        Ok(v.to_string())
    } else if !v.contains('\'') {
        Ok(format!("'{v}'"))
    } else if !v.contains('"') {
        Ok(format!("\"{v}\""))
    } else {
        bail!("{key}: value contains both quote characters; set it by hand")
    }
}

fn apply(lines: &[String], resolved: &[(String, Resolved)]) -> Result<(Vec<String>, Vec<(String, Status)>)> {
    let mut out = lines.to_vec();
    let mut report = Vec::new();
    for (key, r) in resolved {
        let idx: Vec<usize> = out
            .iter()
            .enumerate()
            .filter(|(_, l)| split_line(l).is_some_and(|(k, _)| k == key))
            .map(|(i, _)| i)
            .collect();
        let value = match r {
            Resolved::Keep => {
                report.push((key.clone(), Status::Kept));
                continue;
            }
            Resolved::Declined => {
                report.push((key.clone(), Status::Declined));
                continue;
            }
            Resolved::Set(v) => v,
        };
        if idx.is_empty() {
            out.push(format!("{key}={}", format_value(key, value)?));
            report.push((key.clone(), Status::Added));
            continue;
        }
        // Rewrite every occurrence, so whichever one the agent's parser honours is right.
        let mut changed = false;
        for i in idx {
            let (_, raw) = split_line(&out[i]).unwrap();
            if unquote(raw) == *value {
                continue;
            }
            let export = if out[i].trim_start().starts_with("export ") { "export " } else { "" };
            out[i] = format!("{export}{key}={}", format_value(key, value)?);
            changed = true;
        }
        report.push((key.clone(), if changed { Status::Updated } else { Status::Unchanged }));
    }
    Ok((out, report))
}

/// Back up the original, then replace it atomically with the same permissions.
fn write_with_backup(path: &Path, lines: &[String]) -> Result<PathBuf> {
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let mut backup = path.as_os_str().to_owned();
    backup.push(format!(".bak-{stamp}"));
    let backup = PathBuf::from(backup);
    std::fs::copy(path, &backup).with_context(|| format!("backing up to {}", backup.display()))?;

    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".owpurge-tmp");
    let tmp = PathBuf::from(tmp);
    let mut body = lines.join("\n");
    body.push('\n');
    std::fs::write(&tmp, body).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::set_permissions(&tmp, std::fs::metadata(path)?.permissions())?;
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(backup)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(s: &str) -> Vec<String> {
        s.lines().map(str::to_string).collect()
    }

    #[test]
    fn parses_directives_and_tolerates_spaced_equals() {
        let v = parse_values(
            "# c\nA = x\nB=@prompt\nC=@prompt-url\nD=@random-hex:32\nE=@@lit\nF=\"q v\"\nA=x\n",
        )
        .unwrap();
        assert_eq!(
            v,
            vec![
                ("A".into(), Directive::Literal("x".into())),
                ("B".into(), Directive::Prompt),
                ("C".into(), Directive::PromptUrl),
                ("D".into(), Directive::RandomHex(32)),
                ("E".into(), Directive::Literal("@lit".into())),
                ("F".into(), Directive::Literal("q v".into())),
            ]
        );
    }

    #[test]
    fn conflicting_duplicates_and_unknown_directives_are_rejected() {
        assert!(parse_values("A=1\nA=2\n").is_err());
        assert!(parse_values("A=@nope\n").is_err());
        assert!(parse_values("A=@random-hex:0\n").is_err());
    }

    #[test]
    fn updates_in_place_appends_missing_and_leaves_the_rest() {
        let src = lines("# header\nexport A=old\nKEEP=me\nB = same\nA=old2");
        let resolved = vec![
            ("A".into(), Resolved::Set("new".into())),
            ("B".into(), Resolved::Set("same".into())),
            ("C".into(), Resolved::Set("added".into())),
        ];
        let (out, report) = apply(&src, &resolved).unwrap();
        assert_eq!(out, lines("# header\nexport A=new\nKEEP=me\nB = same\nA=new\nC=added"));
        assert_eq!(
            report,
            vec![
                ("A".into(), Status::Updated),
                ("B".into(), Status::Unchanged),
                ("C".into(), Status::Added),
            ]
        );
    }

    #[test]
    fn random_hex_never_replaces_an_existing_value() {
        let mut never = |_: &str| -> Result<String> { panic!("must not prompt") };
        let d = Directive::RandomHex(32);
        assert_eq!(resolve("K", &d, Some("abc"), &mut never).unwrap(), Resolved::Keep);
        match resolve("K", &d, Some(""), &mut never).unwrap() {
            Resolved::Set(v) => assert!(v.len() == 64 && v.chars().all(|c| c.is_ascii_hexdigit())),
            r => panic!("{r:?}"),
        }
    }

    #[test]
    fn prompt_url_strips_trailing_slash_and_blank_keeps_current() {
        let mut answers = vec!["https://a.example/x//\n".to_string(), "not a url\n".into()];
        let mut ask = |_: &str| Ok(answers.pop().unwrap());
        assert_eq!(
            resolve("U", &Directive::PromptUrl, None, &mut ask).unwrap(),
            Resolved::Set("https://a.example/x".into())
        );
        let mut blank = |_: &str| Ok("\n".to_string());
        assert_eq!(resolve("U", &Directive::Prompt, Some("cur"), &mut blank).unwrap(), Resolved::Keep);
    }

    #[test]
    fn values_are_quoted_only_when_needed() {
        assert_eq!(format_value("K", "0xAbC").unwrap(), "0xAbC");
        assert_eq!(format_value("K", "https://h/p?a=1&b=2").unwrap(), "https://h/p?a=1&b=2");
        assert_eq!(format_value("K", "a b#c").unwrap(), "'a b#c'");
        assert_eq!(format_value("K", "it's").unwrap(), "\"it's\"");
        assert!(format_value("K", "a\nb").is_err());
    }

    #[test]
    fn review_masks_secret_looking_fields_only() {
        let mut v = serde_json::json!({
            "walletId": "w1",
            "walletKey": "k",
            "walletPassword": "p",
            "fileServerToken": "",
            "endpoint": ["https://agent.example.org"],
            "nested": { "apiKey": 42, "creds": [{ "privateKey": "x" }] },
            "rpcUrl": "https://rpc.example.org"
        });
        mask_secrets(&mut v);
        assert_eq!(
            v,
            serde_json::json!({
                "walletId": "w1",
                "walletKey": "********",
                "walletPassword": "********",
                "fileServerToken": "",
                "endpoint": ["https://agent.example.org"],
                "nested": { "apiKey": "********", "creds": [{ "privateKey": "********" }] },
                "rpcUrl": "https://rpc.example.org"
            })
        );
    }

    #[test]
    fn only_a_real_replacement_needs_confirmation() {
        let src = lines("A=old\nB=\nC=same\nD=x\nD=y");
        assert_eq!(existing_differs(&src, "A", "new"), Some("old".into()));
        assert_eq!(existing_differs(&src, "B", "new"), None); // empty: just fill it
        assert_eq!(existing_differs(&src, "C", "same"), None);
        assert_eq!(existing_differs(&src, "Z", "new"), None); // missing: append
        assert_eq!(existing_differs(&src, "D", "x"), Some("y".into()));
    }

    #[test]
    fn secret_looking_keys_are_masked_when_shown() {
        assert_eq!(shown("LOG_FORMAT", "json"), "json");
        assert_eq!(shown("API_KEY", "0123456789abcdef"), "********cdef");
        assert_eq!(shown("DB_PASSWORD", "short"), "********");
        assert_eq!(shown("X", ""), "(empty)");
    }

    #[test]
    fn current_value_reads_quotes_and_inline_comments() {
        let cur = current_values(&lines("A=\"x y\"\nB=v # note\nC=1\nC=2"));
        assert_eq!(cur["A"], "x y");
        assert_eq!(cur["B"], "v");
        assert_eq!(cur["C"], "2");
    }
}
