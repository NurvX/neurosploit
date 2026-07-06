#!/usr/bin/env python3
"""
NeuroSploit v3.5.5 — decision / deep-exploitation agents.

Response-analysis-driven agents that reason about WHERE to attack, connect
endpoints, mine parameters, test both auth levels, build PoCs (HTML for
clickjacking/CSRF, scripts for multi-step), and bypass controls. Read-only-first,
non-destructive, authorized only; PII masked. Credits: Joas A Santos & Red Team Leaders.
"""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "agents_md", "vulns")


def render(a):
    L = [f"# {a['title']} Agent\n", "## User Prompt",
         f"You are testing **{{target}}** for {a['for']}.\n",
         "**Recon Context:**\n{recon_json}\n", "**METHODOLOGY:**\n"]
    for i, (s, bs) in enumerate(a["steps"], 1):
        L.append(f"### {i}. {s}")
        L += [f"- {b}" for b in bs]
        L.append("")
    n = len(a["steps"]) + 1
    L += [f"### {n}. Report Format", "For each CONFIRMED finding:", "```", "FINDING:",
          f"- Title: {a['title']} at [endpoint]", f"- Severity: {a['sev']}", f"- CWE: {a['cwe']}",
          "- Endpoint: [full URL]", "- Vector: [what/where]", "- Payload: [exact request / PoC file path]",
          "- Evidence: [raw request+response / PoC output proving it]", f"- Impact: {a['impact']}",
          f"- Remediation: {a['fix']}", "```\n", "## System Prompt", a["system"]]
    return "\n".join(L) + "\n"


def A(name, title, vc, cwe, sev, steps, fix, impact):
    return {"name": name, "title": title, "for": vc, "sev": sev, "cwe": cwe, "impact": impact, "fix": fix,
            "steps": steps,
            "system": (f"You are a specialist in {vc}. AUTHORIZED engagement. ANALYSE responses first, then act — "
                       "let the evidence pick the technique. Connect endpoints and reuse any session you obtain. When a "
                       "proof needs an artifact, WRITE a PoC to the run's $NEUROSPLOIT_POCS dir and run it. Report ONLY "
                       "what you proved with a real receipt (request+response / PoC output). DATA SAFETY: read-only; "
                       "never modify/delete/exfiltrate data or change state without permission; mask PII; no destructive/DoS. "
                       "Credits: Joas A Santos and Red Team Leaders.")}


AGENTS = [
 A("param_miner", "Parameter Discovery & Testing", "hidden/undocumented parameters and per-parameter vulnerabilities",
   "CWE-20", "Medium",
   [("Discover", ["Enumerate query/body/header/cookie params from responses, JS bundles, source maps and forms; add "
                  "plausible ones the API may accept (id, user, role, admin, debug, redirect, file, callback, format)"]),
    ("Reason per param", ["For each param, infer its purpose from the response and pick the fitting test: IDOR (ids), "
                          "injection (queries/filters), path traversal (file/path), open-redirect (url/next/redirect), "
                          "SSRF (url/callback), mass-assignment (role/isAdmin)"]),
    ("Test & confirm", ["Send the targeted payload; use response DIFFERENTIALS (valid vs invalid, present vs absent) to "
                        "confirm the parameter is exploitable"])],
   "Validate & allow-list every parameter server-side; never trust hidden/undocumented inputs",
   "Varies by parameter — up to injection / IDOR / SSRF"),

 A("endpoint_flow_linker", "Endpoint Flow & Chain Analyst", "sensitive multi-step flows built by linking endpoints",
   "CWE-840", "High",
   [("Map the graph", ["Build the route/endpoint graph; note which endpoint's output (id, token, filename, URL) feeds "
                       "another endpoint's input"]),
    ("Find sensitive flows", ["Trace flows through auth, password reset, payment, file up/download, account/role change, "
                              "admin, export — the ones with real impact"]),
    ("Attack the seam", ["Tamper the value passed between steps (swap an id/token, skip a step, replay, reorder) and see "
                         "if the server accepts an invalid state; connect the finding to what it unlocks downstream"])],
   "Enforce server-side authorization & state validation at EVERY step; sign/scope inter-step tokens",
   "Broken workflow → data access / privilege abuse"),

 A("authenticated_surface_exploit", "Authenticated Surface Exploitation", "vulnerabilities reachable only after authentication",
   "CWE-306", "High",
   [("Authenticate", ["Use the provided creds/roles or perform the login flow; capture and REUSE the session/JWT/cookie"]),
    ("Enumerate authed surface", ["List endpoints/params only reachable while logged in (account, settings, orders, "
                                  "admin, API); mock realistic data where a valid body is needed to go deeper"]),
    ("Exploit & compare roles", ["Test those authenticated endpoints for IDOR/injection/mass-assignment/logic; if you "
                                 "have multiple roles (user AND admin), run as each and compare who can reach what"])],
   "Authorize every authenticated endpoint by the session user/role; least privilege",
   "High-impact bugs on the privileged surface"),

 A("clickjacking_poc", "Clickjacking PoC Builder", "clickjacking / UI redress on state-changing pages",
   "CWE-1021", "Medium",
   [("Check framing", ["Inspect X-Frame-Options and CSP frame-ancestors on sensitive/state-changing pages; if absent or "
                       "permissive, the page is framable"]),
    ("Build a PoC", ["WRITE an HTML PoC to $NEUROSPLOIT_POCS that frames the target page with a decoy overlay (an "
                     "`<iframe src=... style=opacity:.0001>` under a bait button), and open/render it to prove the page "
                     "loads inside the frame — capture a screenshot"]),
    ("Confirm impact", ["Show the framed page hosts a sensitive action (delete, transfer, change email) that a user could "
                        "be tricked into clicking"])],
   "Send X-Frame-Options: DENY or CSP frame-ancestors 'none'/'self' on all sensitive pages",
   "Tricked state-changing actions / account changes"),

 A("csrf_poc", "CSRF PoC Builder", "cross-site request forgery on state-changing requests",
   "CWE-352", "High",
   [("Find state-changing requests", ["Identify POST/PUT/DELETE/PATCH that change state; check for an anti-CSRF token and "
                                       "SameSite cookie attributes"]),
    ("Assess protection", ["Determine if the request succeeds WITHOUT a valid token / from a cross-site context (missing "
                           "token, token not validated, SameSite=None or absent)"]),
    ("Build a PoC", ["WRITE an auto-submitting HTML form PoC to $NEUROSPLOIT_POCS that replays the request cross-site; "
                     "confirm the state change occurs (prove with the resulting response — never cause real damage)"])],
   "Require a validated anti-CSRF token; set SameSite=Lax/Strict on session cookies; re-auth sensitive actions",
   "Unauthorized state change on the victim's behalf"),

 A("access_control_bypass", "Access-Control Bypass", "bypassing 401/403/redirect and other access controls",
   "CWE-284", "High",
   [("Find the block", ["Identify endpoints that return 401/403/redirect or are hidden from your role"]),
    ("Try bypasses", ["Verb tampering (GET↔POST↔PUT, HEAD, OPTIONS), path/case/encoding normalization (`//`, `/.`, "
                      "`%2e`, trailing dot, `;`), header spoofing (X-Original-URL, X-Rewrite-URL, X-Forwarded-For/Host, "
                      "Referer), missing-vs-invalid token, and direct object/API access behind the UI"]),
    ("Confirm", ["Show the two requests (blocked vs bypassed) and the protected data/action reached via the bypass"])],
   "Consistent server-side authorization independent of method/path formatting/headers; canonicalize before authz",
   "Unauthorized access to protected resources/actions"),
]


def main():
    os.makedirs(OUT, exist_ok=True)
    for a in AGENTS:
        open(os.path.join(OUT, a["name"] + ".md"), "w").write(render(a))
    print(f"wrote {len(AGENTS)} decision/deep-exploitation agents to {OUT}")


if __name__ == "__main__":
    main()
