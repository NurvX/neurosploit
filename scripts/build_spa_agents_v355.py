#!/usr/bin/env python3
"""
NeuroSploit v3.5.5 — SPA / API-driven application agents (browser-first).

Targets modern single-page apps (Angular/React/Vue) and their REST/GraphQL
backends — e.g. OWASP Juice Shop. These agents DRIVE A REAL BROWSER (Playwright
MCP when available, else the Playwright CLI) to render the app, enumerate
client-side routes, watch the network, and prove client-side issues — then use
curl for the discovered API. Read-only-first, non-destructive, authorized only.
Credits: Joas A Santos & Red Team Leaders.
"""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "agents_md", "vulns")

BROWSER_NOTE = ("This target is likely a JS-rendered SPA: curl sees only an empty shell, so you MUST use the "
                "browser (Playwright MCP if available, otherwise a Playwright CLI script) to render and interact, "
                "and watch the network to discover the real API.")


def render(a):
    L = [f"# {a['title']} Agent\n", "## User Prompt",
         f"You are testing **{{target}}** for {a['for']}.\n",
         f"> {BROWSER_NOTE}\n",
         "**Recon Context:**\n{recon_json}\n", "**METHODOLOGY:**\n"]
    for i, (s, bs) in enumerate(a["steps"], 1):
        L.append(f"### {i}. {s}")
        L += [f"- {b}" for b in bs]
        L.append("")
    n = len(a["steps"]) + 1
    L += [f"### {n}. Report Format", "For each CONFIRMED finding:", "```", "FINDING:",
          f"- Title: {a['title']} at [route/endpoint]", f"- Severity: {a['sev']}", f"- CWE: {a['cwe']}",
          "- Endpoint: [route or API URL]", "- Vector: [what/where]", "- Payload: [exact payload/request]",
          "- Evidence: [rendered DOM / network request+response / screenshot path proving it]",
          f"- Impact: {a['impact']}", f"- Remediation: {a['fix']}", "```\n", "## System Prompt", a["system"]]
    return "\n".join(L) + "\n"


def A(name, title, vc, cwe, sev, steps, fix, impact):
    return {"name": name, "title": title, "for": vc, "sev": sev, "cwe": cwe, "impact": impact, "fix": fix,
            "steps": steps,
            "system": (f"You are a specialist in {vc} on modern SPA/API apps. AUTHORIZED engagement. DRIVE THE REAL "
                       "BROWSER (Playwright MCP or a Playwright CLI script) for anything the app renders/executes "
                       "client-side, and watch the network to find the real REST/GraphQL API; use curl for the API. "
                       "Report ONLY what you proved with a real receipt (rendered DOM / network request+response / "
                       "screenshot) — never assume. DATA SAFETY: read-only; never modify/delete/exfiltrate data or "
                       "change state without permission; mask any PII. No destructive/DoS. "
                       "Credits: Joas A Santos and Red Team Leaders.")}


AGENTS = [
 A("spa_api_discovery", "SPA API & Route Discovery", "mapping a JS SPA's client-side routes and backend API",
   "CWE-200", "Info",
   [("Render & watch", ["Open the app in the browser, wait for it to render, and record every XHR/fetch the app makes "
                        "(method, URL, body) — that reveals the real REST/GraphQL API behind the SPA"]),
    ("Enumerate routes", ["Extract client-side routes from the router config in the bundled JS and by navigating "
                          "(e.g. #/login, #/admin, #/administration, #/score-board, #/accounting); note gated/hidden ones"]),
    ("Map the API", ["List each API base/path (e.g. /rest/*, /api/*, /graphql), its params, auth requirement, and shape",
                     "Fetch and grep the JS bundles + any source maps for endpoints, params and secrets"]),
    ("Handoff", ["Produce a route+API map so the specialist agents know exactly where to test"])],
   "Don't ship route/API details or source maps to prod; require auth on sensitive routes; least data",
   "Full client + API attack-surface map"),

 A("spa_hidden_admin", "Hidden Admin & Client-Side Access Control", "client-side-only access control (hidden admin/features)",
   "CWE-602", "High",
   [("Find gated routes", ["From the router/JS, find admin/privileged routes and feature flags (e.g. #/administration, "
                           "score-board, accounting) that the UI hides but the router still resolves"]),
    ("Navigate directly", ["Browse straight to the gated route as a low-priv/anon user; if the page renders and its API "
                           "calls succeed, access control is only client-side"]),
    ("Confirm at the API", ["Call the underlying admin API directly (curl) as the low-priv role and show it returns data/allows the action"])],
   "Enforce authorization SERVER-SIDE on every route's API; never rely on hiding UI",
   "Unauthorized admin access / privileged data & actions"),

 A("login_sqli_bypass", "Authentication SQLi Bypass", "SQL injection in the login/auth flow to bypass authentication",
   "CWE-89", "Critical",
   [("Locate login", ["Identify the login API the SPA calls (watch the network on a login attempt)"]),
    ("Inject", ["Try auth-bypass payloads in the identifier field, e.g. `' OR 1=1--`, `admin'--`, `' OR '1'='1`; "
                "observe whether a session/JWT is issued without valid credentials"]),
    ("Confirm", ["Show a token/session returned for an injected credential, then use it to reach an authenticated resource"])],
   "Parameterize queries / use an ORM; never build SQL from input; generic auth errors",
   "Full authentication bypass / account takeover"),

 A("dom_xss_spa", "SPA DOM-Based XSS", "DOM-based XSS via client-side sinks in a JS SPA",
   "CWE-79", "High",
   [("Find sinks", ["From rendered pages and JS, find inputs reflected into the DOM via dangerous sinks "
                    "(innerHTML, bypassSecurityTrust*, v-html, dangerouslySetInnerHTML, location/hash handlers)"]),
    ("Fire it", ["Deliver a payload through the URL fragment/search or an input (e.g. #/search?q=<img src=x onerror=…>) "
                 "and CONFIRM script execution IN THE BROWSER (dialog/DOM change/JS callback), with a screenshot"]),
    ("Scope", ["Note reflected vs stored, and whether it needs interaction"])],
   "Contextual output encoding; framework auto-escaping; avoid bypassSecurityTrust/innerHTML; CSP",
   "Session/token theft, account takeover, UI redress"),

 A("api_bola_numeric_ids", "API BOLA via Sequential IDs", "broken object level authorization on numeric API IDs",
   "CWE-639", "High",
   [("Capture own IDs", ["As a low-priv user, capture the numeric IDs of your own objects (basket, order, user, review) from the API"]),
    ("Cross-access", ["Change the ID to another user's (id-1, id+1, enumerate) on GET/PUT/DELETE and see if you reach their object",
                      "Also try the object under a different collection (e.g. /api/Users/{id}, /rest/basket/{id})"]),
    ("Confirm", ["Show reading or modifying another user's object; prove with the two requests (yours vs theirs). Mask PII"])],
   "Authorize every object access against the session user server-side; use unguessable IDs",
   "Cross-user data read/modification"),

 A("register_privilege_mass_assign", "Privileged Registration / Mass Assignment", "elevating privilege via extra fields on register/update",
   "CWE-915", "High",
   [("Inspect the model", ["Watch the register/profile-update API request and infer server-side fields "
                           "(e.g. role, isAdmin, deluxeToken) not shown in the UI"]),
    ("Inject fields", ["Add the privileged field (e.g. \"role\":\"admin\") to the register/update body and submit"]),
    ("Confirm", ["Show the account was created/updated with the elevated attribute and can reach admin-only resources"])],
   "Server-side allow-list of writable fields (DTO); never bind role/permission from client input",
   "Privilege escalation to admin"),

 A("jwt_forgery_spa", "JWT Forgery & Verification Bypass", "forgeable/weak JWT accepted by the API",
   "CWE-347", "Critical",
   [("Grab a token", ["Log in (browser or API) and capture the JWT the SPA stores/sends (Authorization/cookie)"]),
    ("Attack the signature", ["Test alg:none (strip signature), RS→HS confusion (sign with the public key as HMAC secret), "
                              "and weak HS256 secret cracking; forge a token with elevated claims (e.g. admin email/role)"]),
    ("Confirm", ["Show the forged token is ACCEPTED by an authenticated API endpoint (server didn't verify properly)"])],
   "Verify signature with a strong secret/correct alg; pin the algorithm; reject alg:none",
   "Authentication bypass / account takeover"),

 A("spa_business_logic", "SPA Business-Logic Abuse", "business-logic flaws in cart/checkout/coupon/workflow",
   "CWE-840", "High",
   [("Model the flow", ["Map the multi-step flow via the browser + its API (cart → basket item → checkout → order)"]),
    ("Break invariants (non-destructive)", ["Test negative/zero/huge quantities, client-set prices, reusing/forging coupons, "
                                            "skipping steps, or tampering totals in the API request — WITHOUT completing a real "
                                            "fraudulent purchase or altering others' data"]),
    ("Confirm", ["Show the server accepted an invalid state (e.g. negative quantity, altered price) in its response"])],
   "Validate all invariants & prices server-side; idempotent coupons; enforce workflow order",
   "Financial loss / integrity abuse"),
]


def main():
    os.makedirs(OUT, exist_ok=True)
    for a in AGENTS:
        open(os.path.join(OUT, a["name"] + ".md"), "w").write(render(a))
    print(f"wrote {len(AGENTS)} SPA/API agents to {OUT}")


if __name__ == "__main__":
    main()
