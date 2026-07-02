#!/usr/bin/env python3
"""
NeuroSploit v3.5.5 — cloud infrastructure test agents.

Adds AWS / GCP / Azure cloud-security agents to agents_md/infra/. They drive the
provider CLIs (`aws`, `gcloud`/`gsutil`, `az`) using credentials the operator
supplies via creds.yaml (aws:/gcp:/azure: blocks, exported to the environment).
Read-only enumeration first, non-destructive, authorized only.
Credits: Joas A Santos & Red Team Leaders.
"""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "agents_md", "infra")
CREDITS = "Credits: Joas A Santos and Red Team Leaders."


def render(a):
    L = [f"# {a['title']} Agent\n", "## User Prompt",
         f"You are testing the **{a['cloud']}** cloud account/target **{{target}}** for {a['for']}.\n",
         "**Recon Context:**\n{recon_json}\n",
         f"**ACCESS:** {a['access']}\n",
         "**METHODOLOGY:**\n"]
    for i, (s, bs) in enumerate(a["steps"], 1):
        L.append(f"### {i}. {s}")
        L += [f"- {b}" for b in bs]
        L.append("")
    n = len(a["steps"]) + 1
    L += [f"### {n}. Report Format", "For each CONFIRMED finding:", "```", "FINDING:",
          f"- Title: {a['title']} - [resource]", f"- Severity: {a['sev']}", f"- CWE: {a['cwe']}",
          "- Endpoint: [cloud resource ARN/URI/id]", "- Vector: [what/where]",
          "- Payload: [exact CLI command run]", "- Evidence: [raw CLI output proving it]",
          f"- Impact: {a['impact']}", f"- Remediation: {a['fix']}", "```\n",
          "## System Prompt", a["system"]]
    return "\n".join(L) + "\n"


def A(name, title, cloud, vc, cwe, sev, access, steps, fix, impact):
    return {"name": name, "title": title, "cloud": cloud, "for": vc, "sev": sev, "cwe": cwe,
            "impact": impact, "fix": fix, "steps": steps, "access": access,
            "system": (f"You are a {cloud} cloud-security specialist. AUTHORIZED engagement. Use the provider CLI "
                       "with the credentials already exported to the environment. Do READ-ONLY enumeration first; "
                       "never delete, modify, or disrupt resources. Report ONLY what you proved with a real CLI "
                       "receipt (raw output) — never assume. Confirm the account/identity before claiming a "
                       f"misconfiguration is exploitable. {CREDITS}")}


AWS_ACCESS = "AWS credentials are exported (AWS_ACCESS_KEY_ID/SECRET[/SESSION_TOKEN], region). Use the `aws` CLI; start with `aws sts get-caller-identity`."
GCP_ACCESS = "A GCP service account is active via $GOOGLE_APPLICATION_CREDENTIALS. Run `gcloud auth activate-service-account --key-file=$GOOGLE_APPLICATION_CREDENTIALS`, then use `gcloud`/`gsutil`."
AZ_ACCESS = "An Azure service principal is exported. Authenticate: `az login --service-principal -u $AZURE_CLIENT_ID -p $AZURE_CLIENT_SECRET --tenant $AZURE_TENANT_ID`, then use `az`."

AGENTS = [
 # ---------- generic ----------
 A("cloud_recon_footprint", "Cloud Footprint & Identity Recon", "multi-cloud",
   "identifying the provider, current identity and reachable resources", "CWE-1008", "Info",
   "Whichever provider CLI has credentials exported (aws/gcloud/az).",
   [("Identify identity", ["Determine the active principal: `aws sts get-caller-identity`, `gcloud auth list`+`gcloud config get project`, or `az account show`",
                           "Note account/subscription/project id and whether it's a user, role or service principal"]),
    ("Map reachable services", ["Enumerate what the identity can list across IAM, storage, compute, secrets, functions",
                                "Record every service that returns data vs AccessDenied — this scopes the blast radius"]),
    ("Prioritise", ["Flag high-value reachable resources (secrets, storage, admin roles) for the specialist agents"])],
   "Scope credentials to least privilege; alert on broad list/describe from unexpected principals", "Reconnaissance baseline for cloud attack surface"),

 # ---------- AWS ----------
 A("aws_identity_scope", "AWS Credential Scope & Caller Identity", "AWS",
   "over-privileged or unexpected credential scope", "CWE-269", "Medium", AWS_ACCESS,
   [("Who am I", ["`aws sts get-caller-identity`; resolve the attached identity (user/role)"]),
    ("What can I do", ["Enumerate attached and inline policies (`aws iam list-attached-*-policies`, `get-*-policy`, `list-policies`)",
                       "Simulate key actions with `aws iam simulate-principal-policy` where allowed"]),
    ("Confirm", ["Show the identity holds broad or admin-equivalent permissions it should not"])],
   "Apply least privilege; remove wildcard `*` actions/resources; rotate long-lived keys", "Excessive permissions → account compromise"),
 A("aws_iam_privesc", "AWS IAM Privilege Escalation", "AWS",
   "IAM privilege-escalation paths", "CWE-269", "High", AWS_ACCESS,
   [("Enumerate", ["List users, roles, groups, policies and pass-role / attach-policy / create-* permissions"]),
    ("Find paths", ["Check known escalation primitives: iam:PassRole+lambda/ec2, CreatePolicyVersion, AttachUserPolicy, UpdateAssumeRolePolicy, sts:AssumeRole chains"]),
    ("Confirm safely", ["Prove a path with a non-destructive check (e.g. simulate-principal-policy) or a benign read via the escalated role — never persist changes"])],
   "Remove dangerous IAM permissions from non-admin principals; monitor iam:* and sts:AssumeRole", "Escalation from low-privilege creds to admin"),
 A("aws_s3_exposure", "AWS S3 Bucket Exposure", "AWS",
   "public or misconfigured S3 buckets", "CWE-732", "High", AWS_ACCESS,
   [("Enumerate buckets", ["`aws s3 ls`; for each: `get-bucket-policy`, `get-bucket-acl`, `get-public-access-block`"]),
    ("Assess exposure", ["Identify buckets readable/writable by AllUsers/AuthenticatedUsers or a permissive policy"]),
    ("Confirm", ["List/read a sensitive object to prove exposure (no exfiltration beyond proof)"])],
   "Enable S3 Block Public Access; tighten bucket policies/ACLs; least-privilege access", "Data exposure / tampering"),
 A("aws_secrets_exposure", "AWS Secrets & Parameter Exposure", "AWS",
   "secrets accessible to the current identity", "CWE-522", "High", AWS_ACCESS,
   [("Enumerate", ["`aws secretsmanager list-secrets`, `aws ssm describe-parameters` (and get-parameter --with-decryption where allowed)"]),
    ("Assess", ["Determine which secrets/parameters the identity can read"]),
    ("Confirm", ["Show a readable high-value secret (redact the value in the report; prove access only)"])],
   "Restrict secret resource policies; scope kms:Decrypt; audit access", "Credential/secret disclosure → lateral movement"),
 A("aws_compute_exposure", "AWS EC2 / Network Exposure & IMDS", "AWS",
   "exposed compute, permissive security groups and IMDSv1 SSRF risk", "CWE-284", "High", AWS_ACCESS,
   [("Enumerate", ["`aws ec2 describe-instances`, `describe-security-groups`, `describe-snapshots --owner-ids self`, `describe-images`"]),
    ("Assess", ["Find 0.0.0.0/0 ingress on sensitive ports, public instances, public EBS snapshots/AMIs, and instances allowing IMDSv1"]),
    ("Confirm", ["Show a concrete exposure (e.g. an SG open to the world, a public snapshot, or IMDSv1 enabled enabling SSRF cred theft)"])],
   "Restrict SGs; require IMDSv2; make snapshots/AMIs private", "Network exposure / credential theft via SSRF"),
 A("aws_lambda_review", "AWS Lambda & Resource-Policy Review", "AWS",
   "insecure Lambda configuration and permissive resource policies", "CWE-732", "Medium", AWS_ACCESS,
   [("Enumerate", ["`aws lambda list-functions`, `get-policy`, `get-function-configuration` (env vars)"]),
    ("Assess", ["Look for secrets in env vars, public/loose resource policies, over-privileged execution roles"]),
    ("Confirm", ["Show a function with a permissive policy or plaintext secret"])],
   "Remove secrets from env; scope resource policies & execution roles", "Secret disclosure / unauthorized invoke"),

 # ---------- GCP ----------
 A("gcp_iam_privesc", "GCP IAM Privilege Escalation", "GCP",
   "IAM binding weaknesses and privilege-escalation paths", "CWE-269", "High", GCP_ACCESS,
   [("Enumerate", ["`gcloud projects get-iam-policy $PROJECT`, list roles/bindings for the active SA"]),
    ("Find paths", ["Check escalation primitives: iam.serviceAccounts.actAs/getAccessToken, setIamPolicy, roles.update, deploymentmanager, cloudfunctions deploy as a privileged SA"]),
    ("Confirm safely", ["Prove a path (e.g. impersonate a more-privileged SA with `--impersonate-service-account`) with a benign read"])],
   "Remove actAs/setIamPolicy from low-priv SAs; least privilege; audit bindings", "Escalation to project owner"),
 A("gcp_storage_exposure", "GCP Cloud Storage Exposure", "GCP",
   "public or misconfigured GCS buckets", "CWE-732", "High", GCP_ACCESS,
   [("Enumerate", ["`gsutil ls`; `gsutil iam get gs://<bucket>` for each"]),
    ("Assess", ["Find buckets granting allUsers/allAuthenticatedUsers read/write"]),
    ("Confirm", ["List/read a sensitive object to prove exposure"])],
   "Enforce uniform bucket-level access; remove allUsers bindings; VPC-SC", "Data exposure / tampering"),
 A("gcp_serviceaccount_keys", "GCP Service Account Key & Impersonation", "GCP",
   "service-account key abuse and impersonation", "CWE-522", "High", GCP_ACCESS,
   [("Enumerate", ["List SAs and keys (`gcloud iam service-accounts list`, `keys list`); check actAs/tokenCreator bindings"]),
    ("Assess", ["Identify SAs the identity can impersonate or mint keys for"]),
    ("Confirm", ["Mint a short-lived token via impersonation (non-destructive) to prove access"])],
   "Disable SA key creation; use workload identity; restrict tokenCreator", "Identity theft / lateral movement"),
 A("gcp_compute_exposure", "GCP Compute & Firewall Exposure", "GCP",
   "permissive firewall rules and exposed VMs/metadata", "CWE-284", "High", GCP_ACCESS,
   [("Enumerate", ["`gcloud compute firewall-rules list`, `instances list`, check metadata & OS Login"]),
    ("Assess", ["Find 0.0.0.0/0 ingress, public IPs on sensitive services, project-wide SSH keys, permissive metadata"]),
    ("Confirm", ["Show a world-open firewall rule or an exposed instance"])],
   "Restrict firewall source ranges; least-privilege metadata; OS Login", "Network exposure / compromise"),
 A("gcp_secrets_functions", "GCP Secret Manager & Cloud Functions", "GCP",
   "readable secrets and insecure Cloud Functions", "CWE-522", "High", GCP_ACCESS,
   [("Enumerate", ["`gcloud secrets list` (+ versions access), `gcloud functions list` (+ get-iam-policy, env)"]),
    ("Assess", ["Find secrets the SA can access and functions with public invoker or secrets in env"]),
    ("Confirm", ["Show a readable secret or a public/loose function"])],
   "Scope secret accessor roles; remove allUsers invoker; no secrets in env", "Secret disclosure / unauthorized invoke"),

 # ---------- Azure ----------
 A("azure_rbac_privesc", "Azure RBAC Privilege Escalation", "Azure",
   "role-assignment weaknesses and escalation paths", "CWE-269", "High", AZ_ACCESS,
   [("Enumerate", ["`az role assignment list --all`, `az role definition list`; resolve the SP's roles/scope"]),
    ("Find paths", ["Check for Owner/Contributor/User Access Administrator, or roles allowing Microsoft.Authorization/roleAssignments/write"]),
    ("Confirm safely", ["Prove escalation potential via a benign read at the escalated scope — never assign roles"])],
   "Least-privilege RBAC; avoid Owner/UAA for automation SPs; PIM", "Escalation to subscription owner"),
 A("azure_storage_exposure", "Azure Storage Account Exposure", "Azure",
   "public blob containers and weak storage access", "CWE-732", "High", AZ_ACCESS,
   [("Enumerate", ["`az storage account list`; check `allowBlobPublicAccess`, network rules, list containers"]),
    ("Assess", ["Find containers set to public (blob/container) or accounts allowing public network access"]),
    ("Confirm", ["List/read a blob in a public container to prove exposure"])],
   "Disable public blob access; use private endpoints; SAS with least scope", "Data exposure"),
 A("azure_keyvault_access", "Azure Key Vault Access", "Azure",
   "over-permissive Key Vault access to secrets/keys/certs", "CWE-522", "High", AZ_ACCESS,
   [("Enumerate", ["`az keyvault list`; check access policies / RBAC and network rules"]),
    ("Assess", ["Determine which vault secrets/keys the SP can read"]),
    ("Confirm", ["Show a readable secret (prove access; redact value)"])],
   "Least-privilege vault RBAC/policies; firewall; purge protection", "Secret/key disclosure"),
 A("azure_compute_identity", "Azure VM, NSG & Managed Identity", "Azure",
   "exposed VMs, permissive NSGs and abusable managed identities", "CWE-284", "High", AZ_ACCESS,
   [("Enumerate", ["`az vm list`, `az network nsg list`, check public IPs and attached managed identities"]),
    ("Assess", ["Find NSGs open to 0.0.0.0/0 on sensitive ports, public VMs, and managed identities with broad roles (IMDS token abuse)"]),
    ("Confirm", ["Show a world-open NSG rule or a VM identity with excessive scope"])],
   "Restrict NSGs; least-privilege managed identities; Just-in-Time VM access", "Network exposure / identity abuse"),
 A("azure_entra_enum", "Azure Entra ID (AAD) Enumeration", "Azure",
   "Entra ID app/service-principal weaknesses", "CWE-284", "Medium", AZ_ACCESS,
   [("Enumerate", ["`az ad sp list`, `az ad app list`; review app credentials, API permissions and consent"]),
    ("Assess", ["Find apps with excessive Graph permissions, expired-but-present secrets, or dangerous consent"]),
    ("Confirm", ["Show an over-permissioned or mis-consented app registration"])],
   "Review app API permissions & consent; rotate SP secrets; conditional access", "Tenant-wide permission abuse / phishing consent"),
]


def main():
    os.makedirs(OUT, exist_ok=True)
    for a in AGENTS:
        open(os.path.join(OUT, a["name"] + ".md"), "w").write(render(a))
    print(f"wrote {len(AGENTS)} cloud agents to {OUT}")


if __name__ == "__main__":
    main()
