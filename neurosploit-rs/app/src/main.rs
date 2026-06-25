//! NeuroSploit v3.5.0 — interactive harness + CLI (`run` / `whitebox` / `agents` / `models`).

mod repl;

use clap::{Parser, Subcommand};
use harness::{agents, models::ModelRef, pool::ModelPool, types::RunConfig, RunOutput};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "neurosploit",
    version,
    about = "NeuroSploit v3.5.0 — multi-model autonomous pentest harness",
    long_about = "NeuroSploit v3.5.0 — a Rust multi-model harness that drives a pool of LLMs \
(API key or local subscription: Claude/Codex/Gemini/Grok) to autonomously test a target. \
After recon it INTELLIGENTLY selects only the agents matching the discovered surface, runs \
them in parallel, then validates every finding by cross-model voting before reporting.\n\n\
Run with NO arguments for an interactive wizard.\n\n\
EXAMPLES:\n  \
# Black-box against a known test site (subscription, Opus, browser via Playwright if present)\n  \
neurosploit run http://testphp.vulnweb.com/ --subscription --model anthropic:claude-opus-4-8 --mcp -v\n\n  \
# Black-box via API keys with a multi-model voting panel\n  \
neurosploit run http://testphp.vulnweb.com/ --model anthropic:claude-opus-4-8 --model openai:gpt-5.1 --vote-n 3\n\n  \
# White-box source review of a cloned repo (DVWA)\n  \
git clone https://github.com/digininja/DVWA /tmp/DVWA\n  \
neurosploit whitebox /tmp/DVWA --subscription --model anthropic:claude-opus-4-8 -v\n\n  \
# Offline pipeline self-test (no keys/login)\n  \
neurosploit run http://testphp.vulnweb.com/ --offline\n\n\
TIP: run inside Kali Linux (or `docker run -it kalilinux/kali-rolling`) so curl/nmap/rustscan/ffuf are available."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Black-box: recon → intelligent agent selection → exploit → vote → report.
    Run {
        url: String,
        /// Models as provider:model (repeatable). First is primary; rest fail over + vote.
        #[arg(long = "model")]
        models: Vec<String>,
        #[arg(long, default_value_t = 0)]
        max_agents: usize,
        #[arg(long, default_value_t = 3)]
        vote_n: usize,
        #[arg(long)]
        offline: bool,
        /// Use local agentic CLI subscription (Claude/Codex/Gemini/Grok login).
        #[arg(long)]
        subscription: bool,
        /// Enable Playwright MCP (auto-installed if missing; backends that don't
        /// support MCP fall back to their built-in tools).
        #[arg(long)]
        mcp: bool,
        /// Credentials YAML for authenticated testing (jwt/header/cookie/login).
        #[arg(long)]
        creds: Option<String>,
        /// Free-text focus, e.g. "injection and broken access control".
        #[arg(long)]
        focus: Option<String>,
        /// Verbose: log each agent as it launches, recon, and votes.
        #[arg(short, long)]
        verbose: bool,
    },
    /// White-box: analyse a local repository's source code for vulnerabilities.
    Whitebox {
        path: String,
        #[arg(long = "model")]
        models: Vec<String>,
        #[arg(long, default_value_t = 0)]
        max_agents: usize,
        #[arg(long, default_value_t = 2)]
        vote_n: usize,
        #[arg(long)]
        offline: bool,
        #[arg(long)]
        subscription: bool,
        #[arg(short, long)]
        verbose: bool,
    },
    /// Greybox: review a repo's source AND exploit the running app together.
    Greybox {
        /// Path to the source repository.
        repo: String,
        /// URL of the running application.
        #[arg(long)]
        url: String,
        #[arg(long = "model")]
        models: Vec<String>,
        /// Credentials YAML for authenticated testing (jwt/header/cookie/login).
        #[arg(long)]
        creds: Option<String>,
        /// Free-text focus, e.g. "injection and broken access control".
        #[arg(long)]
        focus: Option<String>,
        #[arg(long, default_value_t = 0)]
        max_agents: usize,
        #[arg(long, default_value_t = 3)]
        vote_n: usize,
        #[arg(long)]
        offline: bool,
        #[arg(long)]
        subscription: bool,
        #[arg(long)]
        mcp: bool,
        #[arg(short, long)]
        verbose: bool,
    },
    /// Show agent library counts.
    Agents,
    /// List providers and models.
    Models,
}

/// Locate the repo root that holds `agents_md/`.
fn find_base() -> PathBuf {
    if let Ok(b) = std::env::var("NEUROSPLOIT_BASE") {
        return PathBuf::from(b);
    }
    if let Ok(cwd) = std::env::current_dir() {
        let mut dir = cwd.as_path();
        for _ in 0..6 {
            if dir.join("agents_md").is_dir() {
                return dir.to_path_buf();
            }
            match dir.parent() {
                Some(p) => dir = p,
                None => break,
            }
        }
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let base = find_base();

    // No subcommand → launch the Claude-Code-style interactive session.
    let cmd = match cli.cmd {
        Some(c) => c,
        None => {
            repl::repl(&base).await?;
            return Ok(());
        }
    };

    match cmd {
        Cmd::Agents => {
            let lib = agents::load(&base);
            println!(
                "{{\"vulns\":{},\"recon\":{},\"code\":{},\"meta\":{},\"total\":{}}}",
                lib.vulns.len(), lib.recon.len(), lib.code.len(), lib.meta.len(), lib.total()
            );
        }
        Cmd::Models => {
            for p in harness::providers() {
                println!("{:<4} {:<14} {} models  [{}]", p.kind, p.key, p.models.len(), p.label);
                for m in &p.models {
                    println!("      {}:{}", p.key, m);
                }
            }
        }
        Cmd::Run { url, models, max_agents, vote_n, offline, subscription, mcp, creds, focus, verbose } => {
            let url = if url.starts_with("http") { url } else { format!("https://{url}") };
            let mut cfg = RunConfig::new(&url);
            cfg.max_agents = max_agents;
            cfg.vote_n = vote_n;
            cfg.offline = offline;
            cfg.subscription = subscription;
            cfg.verbose = verbose;
            cfg.instructions = focus;
            if !models.is_empty() {
                cfg.models = models;
            }
            apply_creds(&mut cfg, creds.as_deref()).await;
            let out = run_engagement(&base, cfg, mcp, false).await?;
            print_findings(&out);
        }
        Cmd::Whitebox { path, models, max_agents, vote_n, offline, subscription, verbose } => {
            let mut cfg = RunConfig::new(&path);
            cfg.max_agents = max_agents;
            cfg.vote_n = vote_n;
            cfg.offline = offline;
            cfg.subscription = subscription;
            cfg.verbose = verbose;
            if !models.is_empty() {
                cfg.models = models;
            }
            let out = run_engagement(&base, cfg, false, true).await?;
            print_findings(&out);
        }
        Cmd::Greybox { repo, url, models, creds, focus, max_agents, vote_n, offline, subscription, mcp, verbose } => {
            let url = if url.starts_with("http") { url } else { format!("https://{url}") };
            let mut cfg = RunConfig::new(&url);
            cfg.repo = Some(repo);
            cfg.max_agents = max_agents;
            cfg.vote_n = vote_n;
            cfg.offline = offline;
            cfg.subscription = subscription;
            cfg.verbose = verbose;
            cfg.instructions = focus;
            if !models.is_empty() {
                cfg.models = models;
            }
            apply_creds(&mut cfg, creds.as_deref()).await;
            let out = run_greybox_engagement(&base, cfg, mcp).await?;
            print_findings(&out);
        }
    }
    Ok(())
}

/// Load a creds.yaml into the run config. Direct material (jwt/header/cookie) is
/// used as-is; a `login:` flow is EXECUTED now (real HTTP) to capture a live
/// session cookie/token. If the auto-login fails, fall back to instructing the
/// agents to authenticate themselves.
pub(crate) async fn apply_creds(cfg: &mut RunConfig, path: Option<&str>) {
    let Some(p) = path else { return };
    let Some(c) = harness::creds::Creds::load(Path::new(p)) else {
        eprintln!("  [!] no usable credentials in {p}");
        return;
    };
    println!("  [*] loaded credentials from {p}");
    if cfg.auth.is_none() {
        cfg.auth = c.auth_header();
    }
    // No direct material but a login flow → perform it now.
    if cfg.auth.is_none() {
        if let Some(login) = &c.login {
            println!("  [*] auto-login: {} {} ...", login.method, login.url);
            match harness::creds::login(login).await {
                Ok((auth, note)) => {
                    println!("  [*] authenticated — {note}");
                    cfg.auth = Some(auth);
                }
                Err(e) => {
                    eprintln!("  [!] auto-login failed ({e}); agents will attempt to log in themselves");
                    if let Some(instr) = c.login_instruction() {
                        let base = cfg.instructions.clone().unwrap_or_default();
                        cfg.instructions = Some(format!("{instr}\n{base}"));
                    }
                }
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Mode { Black, White, Grey }

pub(crate) async fn run_greybox_engagement(base: &Path, cfg: RunConfig, mcp: bool) -> anyhow::Result<RunOutput> {
    run_mode(base, cfg, mcp, Mode::Grey).await
}

/// Shared engagement runner for `run` / `whitebox` / the interactive session.
pub(crate) async fn run_engagement(base: &Path, cfg: RunConfig, mcp: bool, whitebox: bool) -> anyhow::Result<RunOutput> {
    run_mode(base, cfg, mcp, if whitebox { Mode::White } else { Mode::Black }).await
}

async fn run_mode(base: &Path, mut cfg: RunConfig, mcp: bool, mode: Mode) -> anyhow::Result<RunOutput> {
    let lib = agents::load(base);

    // Unique, sortable run id → runs/<id>/
    let run_id = format!("ns-{}-{}", now_ts(), sanitize(&cfg.target));
    let workdir = base.join("runs").join(&run_id);
    std::fs::create_dir_all(&workdir).ok();
    cfg.workdir = Some(workdir.display().to_string());
    cfg.rl_path = Some(base.join("data").join("rl_state_rs.json").display().to_string());
    write_status(&workdir, "running", &format!("\"target\":{:?}", cfg.target));

    println!("  ┌─ NeuroSploit v3.5.0  ·  by Joas A Santos & Red Team Leaders");
    println!("  │  run id : {run_id}");
    println!("  │  target : {}", cfg.target);
    println!("  │  models : {}", cfg.models.join(", "));
    println!("  │  output : {}", workdir.display());
    if let Mode::Grey = mode {
        println!("  │  repo   : {}", cfg.repo.clone().unwrap_or_default());
    }
    println!("  └─ mode   : {}{}{}",
        match mode { Mode::White => "white-box", Mode::Grey => "greybox", Mode::Black => "black-box" },
        if cfg.subscription { " · subscription" } else { " · api" },
        if mcp { " · mcp" } else { "" });

    // Playwright MCP: only for backends that support it; auto-provision if asked.
    let mcp_config = if mcp && cfg.subscription {
        let providers: Vec<String> = cfg.models.iter().map(|m| ModelRef::parse(m).provider).collect();
        if providers.iter().any(|p| harness::mcp_supported(p)) {
            match harness::ensure_playwright_mcp() {
                Ok(()) => {
                    // Optional user-supplied extra MCP servers merged into the pipeline.
                    let extra = base.join("mcp.servers.json");
                    let extra_ref = if extra.is_file() { Some(extra.as_path()) } else { None };
                    match harness::write_mcp_config(&workdir, extra_ref) {
                    Ok(p) => {
                        if extra_ref.is_some() { println!("  [*] merged extra MCP servers from mcp.servers.json"); }
                        println!("  [*] Playwright MCP ready → {}", p.display());
                        Some(p.display().to_string())
                    }
                    Err(e) => { eprintln!("  [!] MCP config failed: {e}"); None }
                    }
                }
                Err(e) => { eprintln!("  [!] Playwright MCP unavailable ({e}); using built-in tools"); None }
            }
        } else {
            eprintln!("  [!] selected backend(s) don't support MCP; using built-in tools");
            None
        }
    } else {
        None
    };

    let refs: Vec<ModelRef> = cfg.models.iter().map(|s| ModelRef::parse(s)).collect();
    let pool = ModelPool::with_auth(refs, cfg.concurrency, cfg.subscription, mcp_config);

    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(256);
    let printer = tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            render_line(&line);
        }
    });
    let out = match mode {
        Mode::White => harness::run_whitebox(cfg, &lib, &pool, tx).await,
        Mode::Grey => harness::run_greybox(cfg, &lib, &pool, tx).await,
        Mode::Black => harness::run(cfg, &lib, &pool, tx).await,
    };
    let _ = printer.await;

    // Final report via Typst (PDF if the `typst` binary is present) + HTML/MD already written.
    match harness::report::typst_report(&out.target, &out.findings, &workdir) {
        Ok(p) => println!("  [*] report → {}", p.display()),
        Err(e) => eprintln!("  [!] typst report skipped: {e}"),
    }
    write_status(&workdir, "complete", &format!("\"findings\":{},\"agents_ran\":{}", out.findings.len(), out.agents_ran.len()));
    println!("  ✓ COMPLETE — {} validated finding(s) · status: {}/status.json", out.findings.len(), workdir.display());
    Ok(out)
}

pub(crate) fn print_findings(out: &RunOutput) {
    println!("\n=== {} validated finding(s) ===", out.findings.len());
    println!("{}", serde_json::to_string_pretty(&out.findings).unwrap_or_default());
    if !out.artifacts.is_empty() {
        println!("artifacts: {}", out.artifacts.join(", "));
    }
}

fn sanitize(s: &str) -> String {
    let s = s.replace("https://", "").replace("http://", "");
    let mut o: String = s.chars().map(|c| if c.is_alphanumeric() { c } else { '_' }).collect();
    o.truncate(40);
    let o = o.trim_matches('_').to_string();
    if o.is_empty() { "target".into() } else { o }
}

fn now_ts() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

// ── Activity-feed renderer ─────────────────────────────────────────────────
// Turns the harness's tagged progress stream into a categorized feed: tool/
// command/file events render as compact cards; everything else as a state line
// with an icon, so it's clear what the AI is doing (no "black box").
const RST: &str = "\x1b[0m";

fn render_line(raw: &str) {
    let line = raw.trim_end();
    let (tag, rest) = match line.split_once(": ") {
        Some((t, r)) if matches!(t, "exec" | "danger" | "read" | "edit" | "tool" | "net" | "ai" | "plan") => (t, r),
        _ => ("", line),
    };
    match tag {
        "exec" => card("⌘ command", rest, "\x1b[33m"),
        "danger" => card("⚠ DANGEROUS command", rest, "\x1b[1;31m"),
        "read" => state("📄", "reading", rest, "\x1b[34m"),
        "edit" => state("✏️", "editing", rest, "\x1b[35m"),
        "net" => card("🌐 request", rest, "\x1b[36m"),
        "tool" => state("🔧", "tool", rest, "\x1b[35m"),
        "ai" => state("💬", "", rest, "\x1b[2m"),
        "plan" => state("🧭", "plan", rest, "\x1b[36m"),
        _ => render_untagged(line),
    }
}

fn render_untagged(l: &str) {
    let low = l.to_lowercase();
    if l.starts_with("===") {
        println!("\n\x1b[1;35m▌ {}\x1b[0m", l.trim_matches('=').trim());
    } else if low.contains("✓ complete") || low.contains("validated finding(s)") {
        println!("  \x1b[1;32m✓\x1b[0m {l}");
    } else if low.starts_with("recon") {
        state("🔍", "reconning", l.trim_start_matches("recon").trim_start_matches(' '), "\x1b[36m");
    } else if low.contains("selected") || low.contains("agent selection") || low.contains("heuristic") {
        state("🧭", "planning", l, "\x1b[36m");
    } else if low.starts_with("exploit") || low.starts_with("analyze") || low.contains("launching agent") || low.starts_with("review ") {
        state("🧪", "testing", l, "\x1b[35m");
    } else if low.starts_with("vote") {
        if low.contains("confirmed") { state("✓", "validated", l, "\x1b[32m"); }
        else { state("·", "rejected", l, "\x1b[2m"); }
    } else if low.starts_with("chain") {
        state("🔗", "chaining", l, "\x1b[36m");
    } else if low.contains("report") {
        state("📄", "report", l, "\x1b[34m");
    } else if low.contains("fail") || low.contains("error") || low.starts_with('✗') {
        println!("  \x1b[31m✗\x1b[0m {l}");
    } else {
        println!("  \x1b[2m·\x1b[0m {l}");
    }
}

fn state(icon: &str, kind: &str, msg: &str, color: &str) {
    let k = if kind.is_empty() { String::new() } else { format!("{color}{kind}{RST} ") };
    println!("  {icon} {k}{}", msg.trim());
}

/// Compact card for a tool the AI ran (the "tool runner visual").
fn card(title: &str, body: &str, color: &str) {
    let body = body.trim();
    let width = body.chars().count().min(72);
    let bar = "─".repeat(width.max(title.chars().count()) + 2);
    println!("  {color}╭─ {title} {}{RST}", "─".repeat(bar.len().saturating_sub(title.chars().count() + 3)));
    for chunk in wrap(body, 72) {
        println!("  {color}│{RST} {chunk}");
    }
    println!("  {color}╰{}{RST}", bar);
}

fn wrap(s: &str, w: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for word in s.split_whitespace() {
        if cur.chars().count() + word.chars().count() + 1 > w && !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() { cur.push(' '); }
        cur.push_str(word);
    }
    if !cur.is_empty() { out.push(cur); }
    if out.is_empty() { out.push(String::new()); }
    out
}

fn write_status(workdir: &Path, state: &str, extra: &str) {
    let p = workdir.join("status.json");
    let _ = std::fs::write(&p, format!("{{\"state\":\"{state}\",\"ts\":{}{}}}", now_ts(),
        if extra.is_empty() { String::new() } else { format!(",{extra}") }));
}

