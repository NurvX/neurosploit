use crate::agents::{Agent, Library};
use crate::pool::ModelPool;
use crate::rl::{severity_reward, RlState};
use crate::types::{Finding, RunConfig};
use crate::report;
use futures::stream::{self, StreamExt};
use serde::Serialize;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc::Sender;

/// Result of an engagement run.
#[derive(Default, Serialize)]
pub struct RunOutput {
    pub findings: Vec<Finding>,
    pub agents_ran: Vec<String>,
    pub candidates: usize,
    pub recon: String,
    /// Paths to persisted artifacts (recon/exploit/findings/report), if any.
    pub artifacts: Vec<String>,
}

const RECON_SYS: &str = "You are a web recon specialist. Map the target's attack surface and reply with a compact JSON object (tech, endpoints, auth, apis, ai_features). No prose.";
const VOTE_SYS: &str = "You are an adversarial security validator. Decide if the candidate finding is a REAL, reproducible, exploitable vulnerability with proof. Reply with JSON {\"verdict\":\"confirmed\"|\"rejected\",\"reason\":\"...\"}. Default to rejected when uncertain.";
const CODE_VOTE_SYS: &str = "You are an adversarial source-code reviewer. Decide if the reported issue is a REAL vulnerability in the provided code (reachable, exploitable, not a false positive). Reply JSON {\"verdict\":\"confirmed\"|\"rejected\",\"reason\":\"...\"}.";

/// Black-box web engagement: recon → parallel exploit → N-model vote → report.
pub async fn run(cfg: RunConfig, lib: &Library, pool: &ModelPool, tx: Sender<String>) -> RunOutput {
    let _ = tx
        .send(format!(
            "Loaded {} agents ({} vuln / {} recon / {} code / {} meta) · models: {} · vote_n={} · concurrency={}{}",
            lib.total(), lib.vulns.len(), lib.recon.len(), lib.code.len(), lib.meta.len(),
            pool.candidates.iter().map(|m| m.label()).collect::<Vec<_>>().join(", "),
            cfg.vote_n, cfg.concurrency,
            if pool.mcp_config.is_some() { " · Playwright MCP ON" } else { "" },
        ))
        .await;

    // ---- 1. Recon ------------------------------------------------------
    let recon = if cfg.offline {
        let _ = tx.send("recon: offline mode — skipping model calls".into()).await;
        "{}".to_string()
    } else {
        match pool.complete(RECON_SYS, &format!("Target: {}", cfg.target)).await {
            Ok((m, t)) => {
                let _ = tx.send(format!("recon complete via {}", m.label())).await;
                t
            }
            Err(e) => {
                let _ = tx.send(format!("recon failed ({e}) — continuing with empty recon")).await;
                "{}".to_string()
            }
        }
    };

    // ---- 2. Intelligent, RL-ranked agent selection ---------------------
    let mut rl = cfg.rl_path.as_ref().map(|p| RlState::load(Path::new(p))).unwrap_or_default();
    let mut ranked: Vec<Agent> = lib.vulns.clone();
    ranked.sort_by(|a, b| rl.weight(&b.name).partial_cmp(&rl.weight(&a.name)).unwrap_or(std::cmp::Ordering::Equal));
    let cap = if cfg.max_agents > 0 { cfg.max_agents.min(ranked.len()) } else { ranked.len() };

    if cfg.offline {
        let selected: Vec<Agent> = ranked.into_iter().take(cap).collect();
        let _ = tx.send(format!("selected {} specialist agents (RL-ranked)", selected.len())).await;
        let _ = tx.send("offline: no exploitation performed (provide API keys or --subscription to run live)".into()).await;
        let artifacts = persist(&cfg, &recon, "", &[]);
        return RunOutput { findings: vec![], agents_ran: selected.iter().map(|a| a.name.clone()).collect(), candidates: 0, recon, artifacts };
    }

    // Use the model to pick the agents whose preconditions match the recon —
    // the harness reasons about *which* specialists to run, not all of them.
    let chosen = select_agents(pool, &recon, &ranked, &tx).await;
    let selected: Vec<Agent> = {
        let mut sel: Vec<Agent> = if chosen.is_empty() {
            ranked.clone()
        } else {
            ranked.iter().filter(|a| chosen.iter().any(|c| c == &a.name)).cloned().collect()
        };
        if sel.is_empty() {
            sel = ranked.clone();
        }
        sel.into_iter().take(cap).collect()
    };
    let _ = tx
        .send(format!("intelligently selected {} agent(s) matching recon: {}", selected.len(),
            selected.iter().map(|a| a.name.clone()).collect::<Vec<_>>().join(", ")))
        .await;

    // ---- 3. Exploit (parallel) -----------------------------------------
    let target = cfg.target.clone();
    let raw: Vec<(String, String, Vec<Finding>)> = stream::iter(selected.iter().cloned())
        .map(|ag| {
            let target = target.clone();
            let recon = recon.clone();
            let txc = tx.clone();
            async move {
                let user = format!(
                    "{}\n\nReply ONLY with a JSON array of confirmed findings (may be empty []). \
                     Each item: {{id,title,severity,cwe,endpoint,payload,evidence,impact,remediation,confidence}}.",
                    ag.user.replace("{target}", &target).replace("{recon_json}", &recon)
                );
                match pool.complete(&ag.system, &user).await {
                    Ok((m, text)) => {
                        let f = extract_findings(&text, &ag.name);
                        let _ = txc.send(format!("exploit {} via {} → {} candidate(s)", ag.name, m.label(), f.len())).await;
                        (ag.name.clone(), text, f)
                    }
                    Err(e) => {
                        let _ = txc.send(format!("exploit {} failed: {e}", ag.name)).await;
                        (ag.name.clone(), format!("ERROR: {e}"), vec![])
                    }
                }
            }
        })
        .buffer_unordered(cfg.concurrency)
        .collect()
        .await;

    let transcript = transcript_of(&raw);
    let candidates: Vec<Finding> = raw.iter().flat_map(|(_, _, f)| f.clone()).collect();
    let _ = tx.send(format!("{} candidate finding(s) — validating by {}-model vote", candidates.len(), cfg.vote_n)).await;

    // ---- 4. Validate by N-model voting ---------------------------------
    let findings = validate(candidates, pool, VOTE_SYS, cfg.vote_n, &tx).await;
    finish(cfg, lib, recon, transcript, findings, selected, &mut rl, tx).await
}

/// White-box engagement: analyse a repository's source for vulnerabilities.
pub async fn run_whitebox(cfg: RunConfig, lib: &Library, pool: &ModelPool, tx: Sender<String>) -> RunOutput {
    let _ = tx.send(format!("WHITEBOX · repo: {} · {} code agents · models: {}", cfg.target, lib.code.len(),
        pool.candidates.iter().map(|m| m.label()).collect::<Vec<_>>().join(", "))).await;

    let context = collect_repo_context(Path::new(&cfg.target), 200, 120_000);
    let bytes = context.len();
    let _ = tx.send(format!("collected {} bytes of source context", bytes)).await;
    if bytes == 0 {
        let _ = tx.send("no readable source found at the given path".into()).await;
    }

    let mut rl = cfg.rl_path.as_ref().map(|p| RlState::load(Path::new(p))).unwrap_or_default();
    let mut ranked: Vec<Agent> = if lib.code.is_empty() { lib.vulns.clone() } else { lib.code.clone() };
    ranked.sort_by(|a, b| rl.weight(&b.name).partial_cmp(&rl.weight(&a.name)).unwrap_or(std::cmp::Ordering::Equal));
    let cap = if cfg.max_agents > 0 { cfg.max_agents.min(ranked.len()) } else { ranked.len() };
    let selected: Vec<Agent> = ranked.into_iter().take(cap).collect();
    let _ = tx.send(format!("selected {} code-analysis agents", selected.len())).await;

    if cfg.offline || bytes == 0 {
        let artifacts = persist(&cfg, "{}", &context, &[]);
        return RunOutput { findings: vec![], agents_ran: selected.iter().map(|a| a.name.clone()).collect(), candidates: 0, recon: String::new(), artifacts };
    }

    let raw: Vec<(String, String, Vec<Finding>)> = stream::iter(selected.iter().cloned())
        .map(|ag| {
            let ctx = context.clone();
            let txc = tx.clone();
            async move {
                let user = format!(
                    "{}\n\nSOURCE CODE TO REVIEW:\n```\n{}\n```\n\nReply ONLY with a JSON array of findings (may be empty []). \
                     Each item: {{id,title,severity,cwe,endpoint,payload,evidence,impact,remediation,confidence}} \
                     where `endpoint` is the file:line and `evidence` quotes the vulnerable code.",
                    ag.user.replace("{target}", "the provided repository").replace("{recon_json}", "{}"),
                    ctx
                );
                match pool.complete(&ag.system, &user).await {
                    Ok((m, text)) => {
                        let f = extract_findings(&text, &ag.name);
                        let _ = txc.send(format!("analyze {} via {} → {} candidate(s)", ag.name, m.label(), f.len())).await;
                        (ag.name.clone(), text, f)
                    }
                    Err(e) => {
                        let _ = txc.send(format!("analyze {} failed: {e}", ag.name)).await;
                        (ag.name.clone(), format!("ERROR: {e}"), vec![])
                    }
                }
            }
        })
        .buffer_unordered(cfg.concurrency)
        .collect()
        .await;

    let transcript = transcript_of(&raw);
    let candidates: Vec<Finding> = raw.iter().flat_map(|(_, _, f)| f.clone()).collect();
    let _ = tx.send(format!("{} candidate finding(s) — validating", candidates.len())).await;
    let findings = validate(candidates, pool, CODE_VOTE_SYS, cfg.vote_n, &tx).await;
    finish(cfg, lib, "{}".into(), transcript, findings, selected, &mut rl, tx).await
}

// --------------------------------------------------------------------------- shared

const SELECT_SYS: &str = "You are a penetration-test orchestrator. Given recon of a target and a catalog of specialist agents, choose ONLY the agents whose preconditions clearly match the target's attack surface. Be selective. Reply with a JSON array of agent names (strings) drawn exactly from the catalog. No prose.";

/// Ask the model which agents to run for this recon. Returns chosen agent names
/// (empty on failure → caller falls back to RL-ranked agents).
async fn select_agents(pool: &ModelPool, recon: &str, catalog: &[Agent], tx: &Sender<String>) -> Vec<String> {
    let list = catalog
        .iter()
        .map(|a| format!("{} — {} [{}]", a.name, a.title.replace(" Agent", ""), a.cwe))
        .collect::<Vec<_>>()
        .join("\n");
    let user = format!("RECON:\n{recon}\n\nAGENT CATALOG (name — title [cwe]):\n{list}\n\nReturn a JSON array of agent names to run.");
    match pool.complete(SELECT_SYS, &user).await {
        Ok((m, text)) => {
            let names = parse_string_array(&text);
            let _ = tx.send(format!("agent selection via {} → {} agent(s) chosen", m.label(), names.len())).await;
            names
        }
        Err(e) => {
            let _ = tx.send(format!("agent selection failed ({e}) — falling back to RL ranking")).await;
            vec![]
        }
    }
}

fn parse_string_array(text: &str) -> Vec<String> {
    match (text.find('['), text.rfind(']')) {
        (Some(a), Some(b)) if b > a => serde_json::from_str::<Vec<String>>(&text[a..=b]).unwrap_or_default(),
        _ => vec![],
    }
}

async fn validate(candidates: Vec<Finding>, pool: &ModelPool, sys: &str, vote_n: usize, tx: &Sender<String>) -> Vec<Finding> {
    let validated: Vec<Finding> = stream::iter(candidates.into_iter())
        .map(|mut f| {
            let txc = tx.clone();
            async move {
                let q = format!(
                    "Finding: {} | severity {} | {} | at {} | payload {} | evidence {}",
                    f.title, f.severity, f.cwe, f.endpoint, f.payload, f.evidence
                );
                let (yes, total) = pool.vote(sys, &q, vote_n).await;
                f.validated = total > 0 && yes * 2 >= total;
                f.votes = format!("{yes}/{total}");
                if f.confidence == 0.0 && total > 0 {
                    f.confidence = yes as f64 / total as f64;
                }
                let _ = txc.send(format!("vote {} → {} ({})", f.title, if f.validated { "CONFIRMED" } else { "rejected" }, f.votes)).await;
                f
            }
        })
        .buffer_unordered(pool.candidates.len().max(2))
        .collect()
        .await;
    validated.into_iter().filter(|f| f.validated).collect()
}

async fn finish(cfg: RunConfig, _lib: &Library, recon: String, transcript: String, findings: Vec<Finding>,
                selected: Vec<Agent>, rl: &mut RlState, tx: Sender<String>) -> RunOutput {
    let _ = tx.send(format!("{} validated finding(s)", findings.len())).await;

    // RL update: reward agents that produced validated findings; gently decay idle.
    let hit: std::collections::HashMap<&str, f64> = findings.iter().fold(Default::default(), |mut m, f| {
        let e = m.entry(f.agent.as_str()).or_insert(0.0);
        *e = (*e + severity_reward(&f.severity)).min(1.0);
        m
    });
    for a in &selected {
        let r = hit.get(a.name.as_str()).copied().unwrap_or(-0.05);
        rl.update(&a.name, r);
    }
    rl.runs += 1;
    if let Some(p) = &cfg.rl_path {
        rl.save(Path::new(p));
        let _ = tx.send("RL rewards updated".into()).await;
    }

    let artifacts = persist(&cfg, &recon, &transcript, &findings);
    if !artifacts.is_empty() {
        let _ = tx.send(format!("artifacts saved: {}", artifacts.join(", "))).await;
    }

    RunOutput {
        candidates: findings.len(),
        findings,
        agents_ran: selected.iter().map(|a| a.name.clone()).collect(),
        recon,
        artifacts,
    }
}

/// Write recon/exploit/findings/report as json+md for downstream reuse.
fn persist(cfg: &RunConfig, recon: &str, transcript: &str, findings: &[Finding]) -> Vec<String> {
    let Some(dir) = &cfg.workdir else { return vec![] };
    let dir = PathBuf::from(dir);
    if std::fs::create_dir_all(&dir).is_err() {
        return vec![];
    }
    let mut written = Vec::new();
    let mut put = |name: &str, content: String| {
        let p = dir.join(name);
        if std::fs::write(&p, content).is_ok() {
            written.push(p.display().to_string());
        }
    };
    put("recon.json", recon.to_string());
    put("recon.md", format!("# Recon — {}\n\n```json\n{}\n```\n", cfg.target, recon));
    if !transcript.is_empty() {
        put("exploitation.md", format!("# Agent transcript — {}\n\n{}", cfg.target, transcript));
    }
    put("findings.json", serde_json::to_string_pretty(findings).unwrap_or_else(|_| "[]".into()));
    put("findings.md", findings_md(&cfg.target, findings));
    put("report.html", report::html(&cfg.target, findings));
    written
}

fn findings_md(target: &str, findings: &[Finding]) -> String {
    let mut s = format!("# NeuroSploit findings — {}\n\n{} validated finding(s).\n", target, findings.len());
    for (i, f) in findings.iter().enumerate() {
        s.push_str(&format!(
            "\n## {}. [{}] {}\n- agent: `{}`  CWE: {}  CVSS: {}  votes: {}  confidence: {:.2}\n- endpoint: {}\n\n**Payload**\n```\n{}\n```\n\n**Evidence**\n{}\n\n**Impact:** {}\n\n**Remediation:** {}\n",
            i + 1, f.severity, f.title, f.agent, f.cwe, f.cvss, f.votes, f.confidence, f.endpoint, f.payload, f.evidence, f.impact, f.remediation
        ));
    }
    s
}

fn transcript_of(raw: &[(String, String, Vec<Finding>)]) -> String {
    raw.iter().map(|(n, t, f)| format!("## {} ({} candidate)\n\n{}\n", n, f.len(), t)).collect::<Vec<_>>().join("\n")
}

/// Pull a JSON array (or object) of findings out of a model's reply.
///
/// Models are inconsistent about field types — e.g. `confidence` may be a number
/// (0.9), a numeric string ("0.9"), or a word ("High"); `cvss` may be a number or
/// a string. Strict typed deserialization fails the whole batch on any mismatch,
/// so we parse leniently into `Value` and coerce every field.
fn extract_findings(text: &str, agent: &str) -> Vec<Finding> {
    let slice = match (text.find('['), text.rfind(']')) {
        (Some(a), Some(b)) if b > a => &text[a..=b],
        _ => match (text.find('{'), text.rfind('}')) {
            (Some(a), Some(b)) if b > a => &text[a..=b],
            _ => return vec![],
        },
    };
    let val: serde_json::Value = match serde_json::from_str(slice) {
        Ok(v) => v,
        Err(_) => return vec![],
    };
    let items: Vec<serde_json::Value> = match val {
        serde_json::Value::Array(a) => a,
        serde_json::Value::Object(_) => vec![val],
        _ => return vec![],
    };
    items
        .into_iter()
        .filter_map(|it| {
            let o = it.as_object()?;
            let title = s(o, "title");
            if title.is_empty() {
                return None;
            }
            Some(Finding {
                id: {
                    let id = s(o, "id");
                    if id.is_empty() {
                        format!("{}-{}", agent, title.chars().take(12).collect::<String>())
                    } else {
                        id
                    }
                },
                agent: agent.to_string(),
                title,
                severity: norm_sev(&s(o, "severity")),
                cwe: s(o, "cwe"),
                cvss: s(o, "cvss"),
                endpoint: s(o, "endpoint"),
                payload: s(o, "payload"),
                evidence: s(o, "evidence"),
                impact: s(o, "impact"),
                remediation: s(o, "remediation"),
                confidence: conf(o.get("confidence")),
                validated: false,
                votes: String::new(),
            })
        })
        .collect()
}

/// Coerce any JSON scalar to a trimmed string.
fn s(o: &serde_json::Map<String, serde_json::Value>, k: &str) -> String {
    match o.get(k) {
        Some(serde_json::Value::String(v)) => v.trim().to_string(),
        Some(serde_json::Value::Number(n)) => n.to_string(),
        Some(serde_json::Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

/// Accept confidence as number, numeric string, or qualitative word.
fn conf(v: Option<&serde_json::Value>) -> f64 {
    match v {
        Some(serde_json::Value::Number(n)) => n.as_f64().unwrap_or(0.0),
        Some(serde_json::Value::String(t)) => {
            if let Ok(f) = t.trim().parse::<f64>() {
                f
            } else {
                match t.to_lowercase().as_str() {
                    s if s.contains("critical") || s.contains("very high") => 0.97,
                    s if s.contains("high") => 0.9,
                    s if s.contains("med") => 0.6,
                    s if s.contains("low") => 0.3,
                    _ => 0.0,
                }
            }
        }
        _ => 0.0,
    }
}

fn norm_sev(s: &str) -> String {
    match s.to_lowercase().as_str() {
        x if x.starts_with("crit") => "Critical",
        x if x.starts_with("high") => "High",
        x if x.starts_with("med") => "Medium",
        x if x.starts_with("low") => "Low",
        "" => "Info",
        _ => "Info",
    }
    .to_string()
}

/// Concatenate source files under `root` into a bounded review context.
fn collect_repo_context(root: &Path, max_files: usize, max_bytes: usize) -> String {
    const EXTS: &[&str] = &[
        "rs", "py", "js", "ts", "tsx", "jsx", "go", "java", "php", "rb", "c", "cc", "cpp", "h", "hpp",
        "cs", "kt", "swift", "scala", "sh", "sql", "html", "vue", "yml", "yaml", "tf",
    ];
    let mut out = String::new();
    let mut files = 0usize;
    if !root.exists() {
        return out;
    }
    for entry in walkdir::WalkDir::new(root).max_depth(8).into_iter().flatten() {
        if files >= max_files || out.len() >= max_bytes {
            break;
        }
        let path = entry.path();
        let s = path.to_string_lossy();
        if s.contains("/.git/") || s.contains("/node_modules/") || s.contains("/target/") || s.contains("/vendor/") {
            continue;
        }
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !EXTS.contains(&ext) {
            continue;
        }
        if let Ok(content) = std::fs::read_to_string(path) {
            let rel = path.strip_prefix(root).unwrap_or(path).to_string_lossy();
            let budget = max_bytes.saturating_sub(out.len());
            let take = content.len().min(budget).min(8_000);
            out.push_str(&format!("\n// ===== file: {} =====\n{}\n", rel, &content[..take]));
            files += 1;
        }
    }
    out
}
