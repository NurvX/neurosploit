//! NeuroSploit v3.5.0 — interactive session (Claude-Code / Codex / Cursor-CLI style).
//!
//! Launched when `neurosploit` runs with no subcommand. A persistent REPL with
//! real line editing (arrow-key history recall, Ctrl-A/E/K, paste), model
//! selection (arrow-key multi-select), API-key configuration based on the chosen
//! models, target/repo/auth/instructions, run history, and reports.

use dialoguer::{theme::ColorfulTheme, MultiSelect};
use harness::{agents, types::Finding, types::RunConfig};
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use serde::{Deserialize, Serialize};
use std::io::IsTerminal;
use std::path::Path;

/// A run completed within this session (persisted to disk for /runs across sessions).
#[derive(Serialize, Deserialize, Clone)]
struct RunRecord {
    id: usize,
    mode: String,
    target: String,
    workdir: String,
    findings: Vec<Finding>,
}

struct Session {
    models: Vec<String>,
    subscription: bool,
    mcp: bool,
    vote_n: usize,
    max_agents: usize,
    offline: bool,
    target: Option<String>,
    repo: Option<String>,
    auth: Option<String>,
    creds: Option<String>,
    instructions: Option<String>,
}

impl Default for Session {
    fn default() -> Self {
        Session {
            models: vec!["anthropic:claude-opus-4-8".into()],
            subscription: harness::installed_cli_backends().contains(&"claude"),
            mcp: false,
            vote_n: 3,
            max_agents: 0,
            offline: false,
            target: None,
            repo: None,
            auth: None,
            creds: None,
            instructions: None,
        }
    }
}

const PROMPT: &str = "\x1b[35mneurosploit›\x1b[0m ";

/// Line reader: full rustyline editing when interactive, plain stdin when piped.
enum Reader {
    Rl(Box<DefaultEditor>, std::path::PathBuf),
    Plain(std::io::Stdin),
}

impl Reader {
    fn new(base: &Path) -> Reader {
        if std::io::stdin().is_terminal() {
            if let Ok(mut ed) = DefaultEditor::new() {
                let hist = base.join("data").join("repl_history.txt");
                std::fs::create_dir_all(hist.parent().unwrap()).ok();
                let _ = ed.load_history(&hist);
                return Reader::Rl(Box::new(ed), hist);
            }
        }
        Reader::Plain(std::io::stdin())
    }

    /// Returns None to exit (EOF / Ctrl-D), Some(line) otherwise. Ctrl-C cancels
    /// the current line (returns an empty string) instead of exiting.
    fn read(&mut self) -> Option<String> {
        match self {
            Reader::Rl(ed, hist) => match ed.readline(PROMPT) {
                Ok(l) => {
                    if !l.trim().is_empty() {
                        let _ = ed.add_history_entry(l.as_str());
                        let _ = ed.save_history(hist);
                    }
                    Some(l)
                }
                Err(ReadlineError::Interrupted) => Some(String::new()), // Ctrl-C: cancel line
                Err(_) => None,                                          // Ctrl-D / error: exit
            },
            Reader::Plain(stdin) => {
                use std::io::Write;
                print!("{PROMPT}");
                std::io::stdout().flush().ok();
                let mut s = String::new();
                match stdin.read_line(&mut s) {
                    Ok(0) | Err(_) => None,
                    Ok(_) => Some(s),
                }
            }
        }
    }
}

pub async fn repl(base: &Path) -> anyhow::Result<()> {
    let lib = agents::load(base);
    let backends = harness::installed_cli_backends();
    println!("\x1b[1m");
    println!("  ███╗   ██╗███████╗██╗   ██╗██████╗  ██████╗");
    println!("  ████╗  ██║██╔════╝██║   ██║██╔══██╗██╔═══██╗   NeuroSploit v3.5.0");
    println!("  ██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║   ██║   interactive harness");
    println!("  ██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║   by Joas A Santos");
    println!("  ██║ ╚████║███████╗╚██████╔╝██║  ██║╚██████╔╝   & Red Team Leaders");
    println!("  ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝\x1b[0m");
    println!("  {} agents loaded · detected logins: {}", lib.total(),
        if backends.is_empty() { "none (use API keys)".into() } else { backends.join(", ") });
    println!("  Type \x1b[36m/help\x1b[0m to start, \x1b[36m/run\x1b[0m to launch, \x1b[36m/quit\x1b[0m to exit. (↑/↓ recalls commands)\n");

    let mut s = Session::default();
    let mut history: Vec<RunRecord> = load_runs(base);
    if !history.is_empty() {
        println!("  loaded {} past run(s) — /runs to list\n", history.len());
    }
    let mut reader = Reader::new(base);
    show(&s);

    loop {
        let Some(line) = reader.read() else { println!("\n  bye."); break };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if !line.starts_with('/') {
            s.instructions = Some(line.to_string());
            println!("  focus set: {line}");
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let cmd = parts.next().unwrap_or("");
        let arg = parts.next().unwrap_or("").trim();
        match cmd {
            "/help" | "/?" => help(),
            "/show" | "/config" => show(&s),
            "/providers" => {
                for p in harness::providers() {
                    println!("  [{}] {:<14} {}", p.kind, p.key,
                        p.models.iter().map(|m| format!("{}:{}", p.key, m)).collect::<Vec<_>>().join("  "));
                }
            }
            "/model" | "/models" => {
                if arg.is_empty() {
                    pick_models(&mut s);
                } else {
                    s.models = arg.split([',', ' ']).filter(|x| !x.is_empty()).map(String::from).collect();
                    println!("  models: {}", s.models.join(", "));
                }
            }
            "/key" => key_cmd(&mut s, arg, &mut reader),
            "/sub" | "/subscription" => {
                s.subscription = !matches!(arg, "off" | "false" | "0" | "no");
                println!("  subscription: {}", onoff(s.subscription));
            }
            "/target" | "/url" => {
                let t = if arg.starts_with("http") || arg.is_empty() { arg.to_string() } else { format!("https://{arg}") };
                s.target = if t.is_empty() { None } else { Some(t) };
                println!("  target: {}", s.target.clone().unwrap_or_else(|| "(none)".into()));
            }
            "/repo" => {
                s.repo = if arg.is_empty() { None } else { Some(arg.to_string()) };
                println!("  repo: {}", s.repo.clone().unwrap_or_else(|| "(none)".into()));
            }
            "/auth" => {
                s.auth = if arg.is_empty() { None } else { Some(arg.to_string()) };
                println!("  auth: {}", s.auth.clone().unwrap_or_else(|| "(none)".into()));
            }
            "/creds" => {
                s.creds = if arg.is_empty() { None } else { Some(arg.to_string()) };
                println!("  creds file: {}", s.creds.clone().unwrap_or_else(|| "(none)".into()));
            }
            "/focus" | "/instructions" => {
                s.instructions = if arg.is_empty() { None } else { Some(arg.to_string()) };
                println!("  focus: {}", s.instructions.clone().unwrap_or_else(|| "(none)".into()));
            }
            "/mcp" => { s.mcp = !matches!(arg, "off" | "false" | "0" | "no"); println!("  Playwright MCP: {}", onoff(s.mcp)); }
            "/offline" => { s.offline = !matches!(arg, "off" | "false" | "0" | "no"); println!("  offline: {}", onoff(s.offline)); }
            "/votes" => { s.vote_n = arg.parse().unwrap_or(s.vote_n); println!("  votes: {}", s.vote_n); }
            "/agents" => { s.max_agents = arg.parse().unwrap_or(s.max_agents); println!("  max agents: {}", s.max_agents); }
            "/clear" => { print!("\x1b[2J\x1b[H"); }
            "/run" | "/go" => { run(base, &s, &mut history).await; save_runs(base, &history); }
            "/runs" | "/history" => list_runs(&history),
            "/results" => results(&history, arg),
            "/report" => open_report(&history, arg),
            "/status" => run_status(&history, arg),
            "/quit" | "/exit" | "/q" => { println!("  bye."); break; }
            other => println!("  unknown command '{other}' — try /help"),
        }
    }
    Ok(())
}

/// Arrow-key multi-select of models from the catalog (interactive terminals only).
fn pick_models(s: &mut Session) {
    if !std::io::stdin().is_terminal() {
        println!("  current: {} (use /model <provider:model,...> to set)", s.models.join(", "));
        return;
    }
    let mut ids: Vec<String> = Vec::new();
    for p in harness::providers() {
        for m in &p.models {
            ids.push(format!("{}:{}", p.key, m));
        }
    }
    let defaults: Vec<bool> = ids.iter().map(|id| s.models.contains(id)).collect();
    match MultiSelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Select models (space toggles, ↑/↓ moves, enter confirms)")
        .items(&ids)
        .defaults(&defaults)
        .interact_opt()
    {
        Ok(Some(idx)) if !idx.is_empty() => {
            s.models = idx.into_iter().map(|i| ids[i].clone()).collect();
            println!("  models: {}", s.models.join(", "));
        }
        _ => println!("  models unchanged: {}", s.models.join(", ")),
    }
}

/// Configure API keys based on the selected models: `/key` lists the providers
/// your models need (set/missing) and prompts for missing ones; `/key <prov> <key>`
/// sets one directly.
fn key_cmd(s: &mut Session, arg: &str, reader: &mut Reader) {
    if !arg.is_empty() {
        let mut kp = arg.splitn(2, char::is_whitespace);
        if let (Some(prov), Some(key)) = (kp.next(), kp.next()) {
            set_key(prov, key.trim(), s);
        } else {
            println!("  usage: /key <provider> <api-key>   e.g. /key anthropic sk-ant-...");
        }
        return;
    }
    // No arg → walk the providers required by the selected models.
    let provs: Vec<String> = s.models.iter()
        .map(|m| m.split(':').next().unwrap_or("").to_string())
        .collect::<std::collections::BTreeSet<_>>().into_iter().collect();
    println!("  API keys for your selected models:");
    for prov in &provs {
        let Some(p) = harness::provider_for(prov) else { continue };
        let set = std::env::var(p.env_key).map(|v| !v.is_empty()).unwrap_or(false);
        let mark = if set { "✓ set" } else { "✗ missing" };
        println!("    {prov:<12} {} ({})", mark, p.env_key);
    }
    if std::io::stdin().is_terminal() {
        for prov in &provs {
            let Some(p) = harness::provider_for(prov) else { continue };
            if std::env::var(p.env_key).map(|v| !v.is_empty()).unwrap_or(false) {
                continue;
            }
            if let Reader::Rl(ed, _) = reader {
                match ed.readline(&format!("  paste {prov} key (blank to skip): ")) {
                    Ok(k) if !k.trim().is_empty() => set_key(prov, k.trim(), s),
                    _ => {}
                }
            }
        }
    } else {
        println!("  (set with /key <provider> <key> or export {{ENV}} before launch)");
    }
}

fn set_key(prov: &str, key: &str, s: &mut Session) {
    match harness::provider_for(prov) {
        Some(p) => {
            std::env::set_var(p.env_key, key);
            s.subscription = false;
            println!("  set {} (API mode)", p.env_key);
        }
        None => println!("  unknown provider '{prov}' (see /providers)"),
    }
}

async fn run(base: &Path, s: &Session, history: &mut Vec<RunRecord>) {
    enum M { Black(String), White(String), Grey { url: String, repo: String } }
    let m = match (&s.repo, &s.target) {
        (Some(r), Some(t)) => M::Grey { url: t.clone(), repo: r.clone() },
        (Some(r), None) => M::White(r.clone()),
        (None, Some(t)) => M::Black(t.clone()),
        _ => { println!("  \x1b[31m✗ set a /target <url> and/or /repo <path> first.\x1b[0m"); return; }
    };
    let primary = match &m {
        M::Black(t) | M::White(t) => t.clone(),
        M::Grey { url, .. } => url.clone(),
    };
    let mut cfg = RunConfig::new(&primary);
    cfg.models = s.models.clone();
    cfg.subscription = s.subscription;
    cfg.vote_n = s.vote_n;
    cfg.max_agents = s.max_agents;
    cfg.verbose = true;
    cfg.offline = s.offline;
    cfg.instructions = s.instructions.clone();
    cfg.auth = s.auth.clone();
    if let M::Grey { repo, .. } = &m {
        cfg.repo = Some(repo.clone());
    }
    crate::apply_creds(&mut cfg, s.creds.as_deref()).await;

    let mode = match &m { M::Grey { .. } => "greybox", M::White(_) => "white-box", M::Black(_) => "black-box" };
    let result = match m {
        M::Grey { .. } => crate::run_greybox_engagement(base, cfg, s.mcp).await,
        M::White(_) => crate::run_engagement(base, cfg, false, true).await,
        M::Black(_) => crate::run_engagement(base, cfg, s.mcp, false).await,
    };
    match result {
        Ok(out) => {
            crate::print_findings(&out);
            let id = history.len() + 1;
            println!("  ↳ saved as run #{id} — /results {id} · /report {id} · /status {id}");
            history.push(RunRecord { id, mode: mode.into(), target: primary, workdir: out.workdir.clone(), findings: out.findings.clone() });
        }
        Err(e) => println!("  \x1b[31m✗ run failed: {e}\x1b[0m"),
    }
}

fn runs_path(base: &Path) -> std::path::PathBuf {
    base.join("data").join("repl_runs.json")
}
fn load_runs(base: &Path) -> Vec<RunRecord> {
    std::fs::read_to_string(runs_path(base)).ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}
fn save_runs(base: &Path, history: &[RunRecord]) {
    let p = runs_path(base);
    if let Some(dir) = p.parent() { std::fs::create_dir_all(dir).ok(); }
    if let Ok(j) = serde_json::to_string_pretty(history) { std::fs::write(p, j).ok(); }
}

fn pick<'a>(history: &'a [RunRecord], arg: &str) -> Option<&'a RunRecord> {
    if history.is_empty() { println!("  no runs yet — /run first."); return None; }
    if arg.trim().is_empty() { return history.last(); }
    match arg.trim().parse::<usize>() {
        Ok(n) => history.iter().find(|r| r.id == n).or_else(|| { println!("  no run #{n} (have 1..{})", history.len()); None }),
        Err(_) => { println!("  usage: /results <run-number>"); None }
    }
}

fn sev_counts(f: &[Finding]) -> std::collections::BTreeMap<&str, usize> {
    let mut m = std::collections::BTreeMap::new();
    for x in f { *m.entry(x.severity.as_str()).or_insert(0) += 1; }
    m
}

fn list_runs(history: &[RunRecord]) {
    if history.is_empty() { println!("  no runs yet."); return; }
    println!("  ┌─ runs (this + past sessions)");
    for r in history {
        let c = sev_counts(&r.findings);
        let sev = if c.is_empty() { "0 findings".into() } else { c.iter().map(|(k, v)| format!("{k}:{v}")).collect::<Vec<_>>().join(" ") };
        println!("  │  #{:<2} {:<9} {:<38} {}", r.id, r.mode, trunc(&r.target, 38), sev);
    }
    println!("  └─ /results <n> · /report <n> · /status <n>");
}

fn results(history: &[RunRecord], arg: &str) {
    let Some(r) = pick(history, arg) else { return };
    println!("  ── run #{} ({}) — {} ──", r.id, r.mode, r.target);
    if r.findings.is_empty() { println!("  (no validated findings)"); return; }
    let mut f = r.findings.clone();
    f.sort_by_key(|x| match x.severity.as_str() { "Critical" => 0, "High" => 1, "Medium" => 2, "Low" => 3, _ => 4 });
    for x in &f {
        println!("  • [{}] {}", x.severity, x.title);
        println!("      {} · {} · votes {} · conf {:.2}", x.agent, x.cwe, x.votes, x.confidence);
        if !x.endpoint.is_empty() { println!("      @ {}", x.endpoint); }
    }
    println!("  report: /report {}", r.id);
}

fn open_report(history: &[RunRecord], arg: &str) {
    let Some(r) = pick(history, arg) else { return };
    let dir = Path::new(&r.workdir);
    let pdf = dir.join("report.pdf");
    let file = if pdf.is_file() { pdf } else { dir.join("report.html") };
    if !file.is_file() { println!("  no report file in {}", r.workdir); return; }
    let opener = if cfg!(target_os = "macos") { "open" } else { "xdg-open" };
    match std::process::Command::new(opener).arg(&file).spawn() {
        Ok(_) => println!("  opening {}", file.display()),
        Err(_) => println!("  report: {}", file.display()),
    }
}

fn run_status(history: &[RunRecord], arg: &str) {
    let Some(r) = pick(history, arg) else { return };
    match std::fs::read_to_string(Path::new(&r.workdir).join("status.json")) {
        Ok(txt) => println!("  run #{}: {}", r.id, txt.trim()),
        Err(_) => println!("  run #{}: no status.json ({})", r.id, r.workdir),
    }
}

fn show(s: &Session) {
    let mode = match (&s.repo, &s.target) {
        (Some(_), Some(_)) => "greybox (code + live)",
        (Some(_), None) => "white-box (code)",
        (None, Some(_)) => "black-box (live)",
        _ => "(set /target and/or /repo)",
    };
    println!("  ┌─ session");
    println!("  │  models   : {}", s.models.join(", "));
    println!("  │  auth mode: {}", if s.subscription { "subscription (CLI login)" } else { "API key" });
    println!("  │  mode     : {mode}");
    println!("  │  target   : {}", s.target.clone().unwrap_or_else(|| "(none)".into()));
    println!("  │  repo     : {}", s.repo.clone().unwrap_or_else(|| "(none)".into()));
    println!("  │  auth     : {}", s.auth.clone().unwrap_or_else(|| "(none)".into()));
    println!("  │  creds    : {}", s.creds.clone().unwrap_or_else(|| "(none)".into()));
    println!("  │  focus    : {}", s.instructions.clone().unwrap_or_else(|| "(none — tests everything)".into()));
    println!("  │  opts     : mcp={} offline={} votes={} max-agents={}", onoff(s.mcp), onoff(s.offline), s.vote_n, s.max_agents);
    println!("  └─ /run to launch");
}

fn help() {
    println!("  Commands (↑/↓ recall history · Ctrl-A/E/K edit · Ctrl-C cancels line):");
    println!("    /model [a:b,..]     set models; with no arg → arrow-key multi-select");
    println!("    /providers          list providers & models");
    println!("    /key [prov key]     configure API keys for your models (no arg → guided)");
    println!("    /sub on|off         use local subscription login instead of API key");
    println!("    /target <url>       black-box target URL");
    println!("    /repo <path>        analyse a repo (repo+target = greybox: code + live)");
    println!("    /auth <value>       auth header (e.g. 'Authorization: Bearer <jwt>')");
    println!("    /creds <file.yaml>  credentials (jwt/header/cookie/login) for authed tests");
    println!("    /focus <text>       steer the tests (or just type it); e.g. injection + access control");
    println!("    /mcp on|off         Playwright MCP browser   /offline on|off  self-test");
    println!("    /votes <n>          /agents <n>");
    println!("    /run                launch   ·   /runs   /results [n]   /report [n]   /status [n]");
    println!("    /quit               exit");
}

fn onoff(b: bool) -> &'static str { if b { "on" } else { "off" } }
fn trunc(s: &str, n: usize) -> String { if s.len() <= n { s.to_string() } else { format!("{}…", &s[..n.saturating_sub(1)]) } }
