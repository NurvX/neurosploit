//! Credential loading for authenticated testing (`creds.yaml`).
//!
//! Dependency-free parser for a small YAML subset: flat `key: value` pairs plus
//! one nested `login:` block (2-space indent). Lets the operator hand the
//! harness a JWT / header / cookie, or a login flow the agents should perform so
//! they test the target as an authenticated user.
//!
//! Example `creds.yaml`:
//! ```yaml
//! jwt: eyJhbGciOi...                 # → Authorization: Bearer <jwt>
//! # header: "X-Api-Key: abc123"      # raw header (alternative)
//! # cookie: "session=deadbeef"       # → Cookie: session=deadbeef
//! login:
//!   url: http://app/login
//!   method: POST
//!   username_field: uid
//!   password_field: passw
//!   username: admin
//!   password: admin
//!   success: Logout
//! ```

#[derive(Default, Debug, Clone)]
pub struct Login {
    pub url: String,
    pub method: String,
    pub username_field: String,
    pub password_field: String,
    pub username: String,
    pub password: String,
    pub success: String,
}

/// SSH credentials for Linux host testing.
#[derive(Default, Debug, Clone)]
pub struct Ssh {
    pub host: String,
    pub port: String,   // default 22
    pub user: String,
    pub password: String,
    pub key: String,    // path to a private key
}

/// Windows / Active Directory credentials.
#[derive(Default, Debug, Clone)]
pub struct Win {
    pub host: String,
    pub user: String,
    pub password: String,
    pub domain: String,
    pub hash: String,   // NTLM hash for pass-the-hash (LM:NT or NT)
}

/// Cloud provider credentials for cloud-infra testing (AWS / GCP / Azure).
/// Secrets are read from `creds.yaml` and exported to the process environment so
/// the `aws` / `gcloud` / `az` CLIs the agents use pick them up automatically.
#[derive(Default, Debug, Clone)]
pub struct Cloud {
    // AWS — static keys (access key + secret [+ session token]) OR a named profile.
    pub aws_access_key_id: String,
    pub aws_secret_access_key: String,
    pub aws_session_token: String,
    pub aws_region: String,
    pub aws_profile: String,
    // GCP — a service-account JSON (path, recommended) or inline single-line JSON.
    pub gcp_sa_json: String,
    pub gcp_project: String,
    // Azure — a service principal (recommended for non-interactive automation).
    pub azure_tenant_id: String,
    pub azure_client_id: String,
    pub azure_client_secret: String,
    pub azure_subscription_id: String,
}

impl Cloud {
    fn is_empty(&self) -> bool {
        self.aws_access_key_id.is_empty() && self.aws_profile.is_empty()
            && self.gcp_sa_json.is_empty()
            && self.azure_client_id.is_empty()
    }
}

#[derive(Default, Debug, Clone)]
pub struct Creds {
    pub jwt: Option<String>,
    pub header: Option<String>,
    pub cookie: Option<String>,
    pub login: Option<Login>,
    pub ssh: Option<Ssh>,
    pub win: Option<Win>,
    pub cloud: Option<Cloud>,
}

impl Creds {
    pub fn load(path: &std::path::Path) -> Option<Creds> {
        let text = std::fs::read_to_string(path).ok()?;
        let mut c = Creds::default();
        let mut login = Login { method: "POST".into(), ..Default::default() };
        let mut ssh = Ssh { port: "22".into(), ..Default::default() };
        let mut win = Win::default();
        let mut cloud = Cloud::default();
        let (mut have_login, mut have_ssh, mut have_win) = (false, false, false);
        let mut block = ""; // "", "login", "ssh", "windows", "aws", "gcp", "azure"
        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or("");
            if line.trim().is_empty() {
                continue;
            }
            let indented = line.starts_with(' ') || line.starts_with('\t');
            let (k, v) = match line.split_once(':') {
                Some((k, v)) => (k.trim().to_string(), unquote(v.trim())),
                None => continue,
            };
            // Enter a nested block (header line with empty value).
            if v.is_empty() && !indented {
                block = match k.as_str() {
                    "login" => { have_login = true; "login" }
                    "ssh" => { have_ssh = true; "ssh" }
                    "windows" | "win" | "ad" => { have_win = true; "windows" }
                    "aws" => "aws",
                    "gcp" | "google" | "gcloud" => "gcp",
                    "azure" | "az" => "azure",
                    _ => "",
                };
                continue;
            }
            if indented {
                match block {
                    "login" => match k.as_str() {
                        "url" => login.url = v,
                        "method" => login.method = v.to_uppercase(),
                        "username_field" => login.username_field = v,
                        "password_field" => login.password_field = v,
                        "username" | "user" => login.username = v,
                        "password" | "pass" => login.password = v,
                        "success" => login.success = v,
                        _ => {}
                    },
                    "ssh" => match k.as_str() {
                        "host" | "ip" => ssh.host = v,
                        "port" => ssh.port = v,
                        "user" | "username" => ssh.user = v,
                        "password" | "pass" => ssh.password = v,
                        "key" | "keyfile" | "identity" => ssh.key = v,
                        _ => {}
                    },
                    "windows" => match k.as_str() {
                        "host" | "ip" => win.host = v,
                        "user" | "username" => win.user = v,
                        "password" | "pass" => win.password = v,
                        "domain" => win.domain = v,
                        "hash" | "ntlm" => win.hash = v,
                        _ => {}
                    },
                    "aws" => match k.as_str() {
                        "access_key_id" | "access_key" | "key" => cloud.aws_access_key_id = v,
                        "secret_access_key" | "secret" => cloud.aws_secret_access_key = v,
                        "session_token" | "token" => cloud.aws_session_token = v,
                        "region" => cloud.aws_region = v,
                        "profile" => cloud.aws_profile = v,
                        _ => {}
                    },
                    "gcp" => match k.as_str() {
                        "service_account_json" | "sa_json" | "key" | "keyfile" | "credentials" => cloud.gcp_sa_json = v,
                        "project" | "project_id" => cloud.gcp_project = v,
                        _ => {}
                    },
                    "azure" => match k.as_str() {
                        "tenant_id" | "tenant" => cloud.azure_tenant_id = v,
                        "client_id" | "app_id" => cloud.azure_client_id = v,
                        "client_secret" | "secret" | "password" => cloud.azure_client_secret = v,
                        "subscription_id" | "subscription" => cloud.azure_subscription_id = v,
                        _ => {}
                    },
                    _ => {}
                }
                continue;
            }
            block = "";
            match k.as_str() {
                "jwt" | "token" => c.jwt = Some(v),
                "header" => c.header = Some(v),
                "cookie" => c.cookie = Some(v),
                _ => {}
            }
        }
        if have_login && !login.url.is_empty() { c.login = Some(login); }
        if have_ssh && !ssh.host.is_empty() { c.ssh = Some(ssh); }
        if have_win && !win.host.is_empty() { c.win = Some(win); }
        if !cloud.is_empty() { c.cloud = Some(cloud); }
        if c.jwt.is_none() && c.header.is_none() && c.cookie.is_none()
            && c.login.is_none() && c.ssh.is_none() && c.win.is_none() && c.cloud.is_none() {
            return None;
        }
        Some(c)
    }

    /// Environment variables to export so the `aws`/`gcloud`/`az` CLIs the agents
    /// run pick up the cloud credentials automatically. For inline GCP JSON the
    /// content is written to a temp file and that path is returned.
    pub fn cloud_env(&self) -> Vec<(String, String)> {
        let mut e: Vec<(String, String)> = Vec::new();
        let Some(c) = &self.cloud else { return e };
        // AWS
        if !c.aws_access_key_id.is_empty() {
            e.push(("AWS_ACCESS_KEY_ID".into(), c.aws_access_key_id.clone()));
            e.push(("AWS_SECRET_ACCESS_KEY".into(), c.aws_secret_access_key.clone()));
            if !c.aws_session_token.is_empty() {
                e.push(("AWS_SESSION_TOKEN".into(), c.aws_session_token.clone()));
            }
        }
        if !c.aws_profile.is_empty() { e.push(("AWS_PROFILE".into(), c.aws_profile.clone())); }
        if !c.aws_region.is_empty() {
            e.push(("AWS_DEFAULT_REGION".into(), c.aws_region.clone()));
            e.push(("AWS_REGION".into(), c.aws_region.clone()));
        }
        // GCP — path (recommended) or inline JSON written to a temp file.
        if !c.gcp_sa_json.is_empty() {
            let path = if c.gcp_sa_json.trim_start().starts_with('{') {
                let p = std::env::temp_dir().join("neurosploit-gcp-sa.json");
                let _ = std::fs::write(&p, c.gcp_sa_json.as_bytes());
                p.display().to_string()
            } else {
                c.gcp_sa_json.clone()
            };
            e.push(("GOOGLE_APPLICATION_CREDENTIALS".into(), path));
        }
        if !c.gcp_project.is_empty() {
            e.push(("GOOGLE_CLOUD_PROJECT".into(), c.gcp_project.clone()));
            e.push(("CLOUDSDK_CORE_PROJECT".into(), c.gcp_project.clone()));
        }
        // Azure — service principal env (consumed by `az login --service-principal`).
        if !c.azure_tenant_id.is_empty() { e.push(("AZURE_TENANT_ID".into(), c.azure_tenant_id.clone())); }
        if !c.azure_client_id.is_empty() { e.push(("AZURE_CLIENT_ID".into(), c.azure_client_id.clone())); }
        if !c.azure_client_secret.is_empty() { e.push(("AZURE_CLIENT_SECRET".into(), c.azure_client_secret.clone())); }
        if !c.azure_subscription_id.is_empty() {
            e.push(("AZURE_SUBSCRIPTION_ID".into(), c.azure_subscription_id.clone()));
            e.push(("ARM_SUBSCRIPTION_ID".into(), c.azure_subscription_id.clone()));
        }
        e
    }

    /// A directive telling the agents which cloud creds are available and how to
    /// authenticate the provider CLI, so they enumerate/test the cloud account.
    pub fn cloud_instruction(&self) -> Option<String> {
        let c = self.cloud.as_ref()?;
        let mut s = String::new();
        if !c.aws_access_key_id.is_empty() || !c.aws_profile.is_empty() {
            s.push_str(&format!(
                "AWS ACCESS: credentials are set in the environment{}. Use the `aws` CLI to enumerate and test the account — start with `aws sts get-caller-identity`, then IAM (users/roles/policies, privilege escalation paths), S3 (public/misconfigured buckets), EC2/SG, Lambda, Secrets Manager. Read-only enumeration first; never destructive.\n",
                if c.aws_region.is_empty() { String::new() } else { format!(" (region {})", c.aws_region) }));
        }
        if !c.gcp_sa_json.is_empty() {
            s.push_str(&format!(
                "GCP ACCESS: a service account is available via $GOOGLE_APPLICATION_CREDENTIALS{}. Run `gcloud auth activate-service-account --key-file=$GOOGLE_APPLICATION_CREDENTIALS` first, then enumerate with `gcloud`/`gsutil` — IAM bindings & privilege escalation, buckets, compute, service accounts/keys, Cloud Functions.\n",
                if c.gcp_project.is_empty() { String::new() } else { format!(" (project {})", c.gcp_project) }));
        }
        if !c.azure_client_id.is_empty() {
            s.push_str(
                "AZURE ACCESS: a service principal is set in the environment. Authenticate with `az login --service-principal -u $AZURE_CLIENT_ID -p $AZURE_CLIENT_SECRET --tenant $AZURE_TENANT_ID`, then enumerate with `az` — role assignments (RBAC) & escalation, storage accounts/containers, VMs, Key Vaults, managed identities.\n");
        }
        if s.is_empty() { None } else { Some(s) }
    }

    /// A directive describing the host credentials available to the agents, so
    /// they can authenticate to Linux (SSH) / Windows (AD) hosts.
    pub fn host_instruction(&self) -> Option<String> {
        let mut s = String::new();
        if let Some(h) = &self.ssh {
            let auth = if !h.key.is_empty() { format!("private key {}", h.key) } else { "password (provided)".into() };
            s.push_str(&format!(
                "SSH ACCESS (Linux): host {}:{} as user '{}' via {}. Use `ssh`/`sshpass` to run \
                 enumeration and privilege-escalation checks on the host.\n",
                h.host, h.port, h.user, auth));
        }
        if let Some(w) = &self.win {
            let auth = if !w.hash.is_empty() { "NTLM hash (pass-the-hash)".to_string() } else { "password".into() };
            s.push_str(&format!(
                "WINDOWS/AD ACCESS: host {} domain '{}' as user '{}' via {}. Use tools like \
                 crackmapexec/netexec, impacket, evil-winrm, bloodhound-python for host and AD checks.\n",
                w.host, if w.domain.is_empty() { "(workgroup)" } else { &w.domain }, w.user, auth));
        }
        if s.is_empty() { None } else { Some(s) }
    }

    /// The auth material to send with each request, as a header line.
    pub fn auth_header(&self) -> Option<String> {
        if let Some(h) = &self.header {
            return Some(h.clone());
        }
        if let Some(j) = &self.jwt {
            return Some(format!("Authorization: Bearer {j}"));
        }
        if let Some(ck) = &self.cookie {
            return Some(format!("Cookie: {ck}"));
        }
        None
    }

    /// A directive instructing the agent to authenticate first via curl.
    pub fn login_instruction(&self) -> Option<String> {
        let l = self.login.as_ref()?;
        Some(format!(
            "AUTHENTICATE FIRST: {} {} with {}={} and {}={}; capture the session cookie/token \
             from the response (success indicator: \"{}\") and reuse it on every subsequent request.",
            l.method, l.url, l.username_field, l.username, l.password_field, l.password, l.success
        ))
    }
}

/// Perform the login flow now (real HTTP POST) and return an auth header to
/// reuse on every subsequent request: a `Cookie:` from Set-Cookie, or an
/// `Authorization: Bearer` from a token in the JSON response. Returns
/// (auth_header, note). Redirects are not followed so the login response's
/// Set-Cookie is visible.
pub async fn login(l: &Login) -> anyhow::Result<(String, String)> {
    use reqwest::header::SET_COOKIE;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let form: Vec<(String, String)> = vec![
        (l.username_field.clone(), l.username.clone()),
        (l.password_field.clone(), l.password.clone()),
    ];
    let req = if l.method == "GET" {
        client.get(&l.url).query(&form)
    } else {
        client.post(&l.url).form(&form)
    };
    let resp = req.send().await?;
    let status = resp.status();

    // 1) session cookies from Set-Cookie on the login response
    let mut cookie_pairs = Vec::new();
    for hv in resp.headers().get_all(SET_COOKIE) {
        if let Ok(s) = hv.to_str() {
            if let Some(pair) = s.split(';').next() {
                let p = pair.trim();
                if !p.is_empty() {
                    cookie_pairs.push(p.to_string());
                }
            }
        }
    }
    let body = resp.text().await.unwrap_or_default();

    // 2) bearer token from a JSON response body
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
        for k in ["access_token", "token", "jwt", "id_token", "accessToken"] {
            if let Some(t) = v.get(k).and_then(|x| x.as_str()).filter(|t| !t.is_empty()) {
                return Ok((format!("Authorization: Bearer {t}"), format!("bearer token from JSON `{k}` (HTTP {status})")));
            }
        }
    }
    if !cookie_pairs.is_empty() {
        let cookie = cookie_pairs.join("; ");
        // Soft success check (don't fail hard — many apps 302 on success).
        let ok = l.success.is_empty() || body.contains(&l.success) || status.is_redirection() || status.is_success();
        let note = format!("session cookie captured (HTTP {status}{})", if ok { "" } else { ", success marker not seen" });
        return Ok((format!("Cookie: {cookie}"), note));
    }
    anyhow::bail!("login returned no Set-Cookie or token (HTTP {status})")
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    if (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
        || (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}
