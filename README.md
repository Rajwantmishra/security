# LiteLLM Supply Chain Attack — Impact Checker

> **Attack Date:** March 24, 2026 &nbsp;|&nbsp; **Bad Versions:** `1.82.7` and `1.82.8` &nbsp;|&nbsp; **Severity:** Critical

On March 24, 2026, threat actor **TeamPCP** published two malicious versions of the `litellm` Python package to PyPI after compromising the maintainer's credentials via a poisoned Trivy security scanner. The malicious packages silently harvested credentials, attempted Kubernetes lateral movement, and installed a persistent backdoor.

**You may be affected without knowing it** — LiteLLM is a transitive dependency in many popular AI tools, Cursor, and MCP setups.

---

## What This Repo Contains

| File | Purpose |
|---|---|
| `litellm_impact_checker.py` | Run on any laptop, workstation, VM, or server |
| `databricks_litellm_checker.py` | Run inside Databricks notebooks or Web Terminal |
| `LiteLLM_Impact_Report.txt` | Full written report with remediation steps |

---

## Affected Versions

| Version | Status |
|---|---|
| `1.82.7` | ❌ **MALICIOUS — do not use** |
| `1.82.8` | ❌ **MALICIOUS — do not use** |
| `1.82.6` | ✅ Last known clean version before the attack |
| `1.82.9+` | ✅ Safe — published after attack window closed |

---

## Attack Chain

```
Trivy (security scanner) compromised
        ↓
PyPI maintainer credentials stolen
        ↓
litellm 1.82.7 & 1.82.8 published to PyPI
        ↓
Stage 1 → Credential harvesting (env vars, cloud keys, LLM API keys)
Stage 2 → Kubernetes lateral movement
Stage 3 → Persistent backdoor installed (sysmon.py + systemd service)
```

---

## Quick Start

### No installs required — standard Python library only

```bash
# Clone the repo
git clone https://github.com/your-username/litellm-impact-checker.git
cd litellm-impact-checker

# Run on your machine
python3 litellm_impact_checker.py
```

A timestamped terminal log is automatically saved:
```
litellm_scan_terminal_20260331_211725.txt
```

A structured JSON report is also saved alongside it.

---

## `litellm_impact_checker.py` — 10 Checks

For laptops, workstations, VMs, CI/CD runners, and servers.

| # | Check | What it looks for |
|---|---|---|
| 1 | **LiteLLM version** | Flags `1.82.7` / `1.82.8` as compromised |
| 2 | **`litellm_init.pth`** | Malicious file that executes on every Python startup — scans all site-packages, venvs, conda, pyenv |
| 3 | **Persistence files** | `~/.config/sysmon/sysmon.py` and `sysmon.service` |
| 4 | **Systemd service** | Whether the backdoor is actively running right now |
| 5 | **Suspicious processes** | Live scan for known malicious process names |
| 6 | **Exposed env vars** | AWS, GCP, Azure, OpenAI, Anthropic, Kubernetes, GitHub tokens, etc. |
| 7 | **Credential files** | `~/.aws/credentials`, `~/.kube/config`, `~/.docker/config.json`, etc. |
| 8 | **Docker images** | Scans for any LiteLLM-based images on the host |
| 9 | **pip-audit** | Automated vulnerability scan (if pip-audit is installed) |
| 10 | **CI/CD configs** | GitHub Actions, GitLab CI, Jenkins, CircleCI, Azure Pipelines |

```bash
python3 litellm_impact_checker.py
```

---

## `databricks_litellm_checker.py` — Databricks Clusters

For Databricks notebooks, Web Terminal, and cluster nodes.

**Option A — Notebook cell (recommended):**
1. Create a new Python notebook on the target cluster
2. Paste the entire script into a cell
3. Run — output appears inline, JSON report saved to `/dbfs/tmp/`

**Option B — Web Terminal:**
```bash
# Upload to DBFS first
databricks fs cp ./databricks_litellm_checker.py dbfs:/tmp/

# Then run on the cluster via Web Terminal
python3 /dbfs/tmp/databricks_litellm_checker.py
```

**Option C — Shell magic in a notebook cell:**
```bash
%sh python3 /dbfs/tmp/databricks_litellm_checker.py
```

**What it checks (in addition to the core 10):**
- Databricks secret scopes via `dbutils.secrets`
- Cluster init scripts referencing unpinned or bad litellm versions
- DBFS for dropped malicious files
- Network connections on known backdoor ports
- Requirements files across `/Workspace` and `/dbfs/FileStore`

---

## Indicators of Compromise (IoCs)

If any of these are present, **treat the system as fully compromised:**

```
# Most critical — runs on every Python startup
<python-site-packages>/litellm_init.pth

# Backdoor files
~/.config/sysmon/sysmon.py
~/.config/systemd/user/sysmon.service

# Running service
systemctl --user is-active sysmon  →  "active"
```

---

## If You Find Something CRITICAL

1. **Isolate the machine** — disconnect from network
2. **Do not delete files yet** — preserve for forensic review
3. **Rotate all credentials** immediately:
   - AWS → IAM Console → rotate access keys
   - GCP → IAM → revoke & recreate service account keys
   - Azure → Azure AD → rotate client secrets
   - OpenAI / Anthropic / other LLM keys → rotate in provider dashboard
   - GitHub / GitLab tokens → revoke all
   - Kubernetes → rotate ServiceAccount tokens, audit RBAC
   - Databricks → revoke personal access tokens, rotate secret scopes
4. **Audit logs** — check cloud provider logs for March 24, 2026
5. **Notify your security team**

---

## Sharing Results

Ask everyone to run the script and share the generated log file:

```
litellm_scan_terminal_YYYYMMDD_HHMMSS.txt
```

This file is plain text, contains no credential values (only variable names), and can be safely shared with your security team.

---

## Requirements

- Python 3.7+
- No external packages needed
- Works on Linux, macOS, Windows (WSL)
- `pip-audit` optional — Check 9 is skipped gracefully if not installed

---

## References

- [LiteLLM Official Security Update](https://docs.litellm.ai/blog/security-update-march-2026)
- [Trend Micro: Inside the LiteLLM Supply Chain Compromise](https://www.trendmicro.com/en_us/research/26/c/inside-litellm-supply-chain-compromise.html)
- [Kaspersky: Supply chain attack via Trivy and LiteLLM](https://www.kaspersky.com/blog/critical-supply-chain-attack-trivy-litellm-checkmarx-teampcp/55510/)
- [FutureSearch: litellm 1.82.8 Supply Chain Attack on PyPI](https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/)
- [Snyk: Poisoned Security Scanner Backdooring LiteLLM](https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm/)
- [CyberNews: Critical LiteLLM Supply Chain Attack](https://cybernews.com/security/critical-litellm-supply-chain-attack-sends-shockwaves/)

---

## Author

**Raj** &nbsp;|&nbsp; rajwantmishra@gmail.com

> *Scripts use only the Python standard library. No pip install required.*
