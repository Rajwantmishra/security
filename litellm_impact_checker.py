#!/usr/bin/env python3
"""
LiteLLM Supply Chain Attack - Impact Checker
=============================================
Checks for indicators of compromise from the March 24, 2026 LiteLLM
supply chain attack (versions 1.82.7 and 1.82.8).

Attack chain: TeamPCP compromised Trivy (security scanner) → gained LiteLLM
PyPI maintainer credentials → published malicious packages with:
  - Stage 1: Credential harvesting (env vars, config files, cloud creds)
  - Stage 2: Kubernetes lateral movement
  - Stage 3: Persistent backdoor (sysmon.py + systemd service)

Run with:  python3 litellm_impact_checker.py
"""

import os
import sys
import json
import glob
import shutil
import hashlib
import platform
import subprocess
from pathlib import Path
from datetime import datetime

# ── ANSI colors ─────────────────────────────────────────────────────────────
RED    = "\033[91m"
YEL    = "\033[93m"
GRN    = "\033[92m"
BLU    = "\033[94m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ── Tee logger: prints to terminal AND writes to log file ───────────────────
import re

class TeeLogger:
    """Mirrors every print() to both the terminal and a plain-text log file.
    ANSI color codes are stripped from the log file so it stays readable."""

    ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*m')

    def __init__(self, log_path: Path):
        self._terminal = sys.stdout
        self._log_path = log_path
        self._file = open(log_path, "w", encoding="utf-8", buffering=1)

    def write(self, message):
        self._terminal.write(message)
        clean = self.ANSI_ESCAPE.sub("", message)
        self._file.write(clean)

    def flush(self):
        self._terminal.flush()
        self._file.flush()

    def close(self):
        sys.stdout = self._terminal
        self._file.flush()
        self._file.close()

    def isatty(self):
        return self._terminal.isatty()


def setup_logger() -> tuple:
    """Create a timestamped log file and attach TeeLogger to stdout.
    Returns (log_path, tee_instance)."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = Path(f"litellm_scan_terminal_{ts}.txt")
    tee = TeeLogger(log_path)
    sys.stdout = tee
    return log_path, tee


def banner():
    print(f"""
{BOLD}{RED}╔══════════════════════════════════════════════════════════════╗
║    LiteLLM Supply Chain Attack — Impact Checker              ║
║    Attack Date: March 24, 2026  |  Bad Versions: 1.82.7/8   ║
╚══════════════════════════════════════════════════════════════╝{RESET}
""")

# ── Helpers ──────────────────────────────────────────────────────────────────
findings = []   # list of {severity, category, detail}

def flag(severity, category, detail):
    """severity: CRITICAL | WARNING | INFO"""
    findings.append({"severity": severity, "category": category, "detail": detail})
    color = RED if severity == "CRITICAL" else (YEL if severity == "WARNING" else BLU)
    tag   = f"[{severity}]"
    print(f"  {color}{BOLD}{tag:<12}{RESET} {detail}")

def ok(msg):
    print(f"  {GRN}[OK]{RESET}         {msg}")

def section(title):
    print(f"\n{BOLD}{BLU}{'─'*60}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{BLU}{'─'*60}{RESET}")

def run(cmd, shell=False):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10, shell=shell)
        return r.stdout.strip()
    except Exception:
        return ""

def file_exists(path):
    return Path(path).expanduser().exists()

def get_site_packages():
    """Return all Python site-packages directories on this system."""
    dirs = set()
    # Current interpreter
    try:
        import site
        dirs.update(site.getsitepackages())
        dirs.add(site.getusersitepackages())
    except Exception:
        pass

    # All pythons in PATH
    for py in ["python3", "python", "python3.9", "python3.10",
               "python3.11", "python3.12", "python3.13"]:
        out = run([py, "-c",
                   "import site; print('\\n'.join(site.getsitepackages()))"],
                  shell=False)
        for line in out.splitlines():
            if line.strip():
                dirs.add(line.strip())

    # pipx, conda, pyenv common locations
    extra_roots = [
        Path.home() / ".local" / "lib",
        Path.home() / ".pyenv" / "versions",
        Path("/opt/conda/lib"),
        Path("/usr/local/lib"),
        Path("/usr/lib"),
    ]
    for root in extra_roots:
        if root.exists():
            for p in root.rglob("site-packages"):
                dirs.add(str(p))

    return [d for d in dirs if d and Path(d).exists()]

# ── Check 1: Installed LiteLLM version ──────────────────────────────────────
def check_litellm_version():
    section("CHECK 1 — Installed LiteLLM Version")
    BAD_VERSIONS = {"1.82.7", "1.82.8"}
    found_any = False

    # pip show
    for pip in ["pip", "pip3"]:
        out = run([pip, "show", "litellm"])
        if out:
            for line in out.splitlines():
                if line.lower().startswith("version"):
                    ver = line.split(":", 1)[-1].strip()
                    found_any = True
                    if ver in BAD_VERSIONS:
                        flag("CRITICAL", "VERSION",
                             f"LiteLLM {ver} is installed — MALICIOUS version confirmed!")
                    elif ver < "1.82.7":
                        ok(f"LiteLLM {ver} installed — predates attack window")
                    else:
                        ok(f"LiteLLM {ver} installed — appears safe (patched)")
                    break

    # importlib fallback
    if not found_any:
        try:
            import importlib.metadata
            ver = importlib.metadata.version("litellm")
            found_any = True
            if ver in BAD_VERSIONS:
                flag("CRITICAL", "VERSION",
                     f"LiteLLM {ver} is installed — MALICIOUS version confirmed!")
            else:
                ok(f"LiteLLM {ver} installed — not a bad version")
        except Exception:
            pass

    if not found_any:
        ok("LiteLLM not found in default Python environment")

# ── Check 2: Malicious .pth file ─────────────────────────────────────────────
def check_pth_file():
    section("CHECK 2 — Malicious .pth File (litellm_init.pth)")
    print(f"  {YEL}Scanning all site-packages directories...{RESET}")
    site_pkgs = get_site_packages()
    print(f"  Found {len(site_pkgs)} site-packages location(s)\n")

    pth_found = False
    for sp in site_pkgs:
        pth = Path(sp) / "litellm_init.pth"
        if pth.exists():
            pth_found = True
            flag("CRITICAL", "PTH_FILE",
                 f"FOUND: {pth}")
            flag("CRITICAL", "PTH_FILE",
                 "This .pth file executes on EVERY Python startup — "
                 "treat system as fully compromised")
            # Try to show its content safely
            try:
                content = pth.read_text(errors="replace")[:500]
                print(f"\n  {RED}--- File content (first 500 chars) ---{RESET}")
                print(f"  {content}")
                print(f"  {RED}--------------------------------------{RESET}\n")
            except Exception as e:
                flag("WARNING", "PTH_FILE", f"Could not read file: {e}")

    if not pth_found:
        ok("litellm_init.pth NOT found in any site-packages")

# ── Check 3: Persistence backdoor files ──────────────────────────────────────
def check_persistence_files():
    section("CHECK 3 — Backdoor Persistence Files")

    ioc_files = [
        ("~/.config/sysmon/sysmon.py",             "CRITICAL", "Backdoor script"),
        ("~/.config/systemd/user/sysmon.service",  "CRITICAL", "Systemd persistence unit"),
        ("~/.config/sysmon/",                      "WARNING",  "Sysmon config directory"),
    ]

    for path_str, severity, desc in ioc_files:
        full = Path(path_str).expanduser()
        if full.exists():
            flag(severity, "PERSISTENCE", f"FOUND — {desc}: {full}")
            if full.is_file():
                try:
                    snippet = full.read_text(errors="replace")[:300]
                    print(f"  {RED}  Content preview:{RESET} {snippet[:200]}...")
                except Exception:
                    pass
        else:
            ok(f"Not present: {full}")

# ── Check 4: Systemd service active? ─────────────────────────────────────────
def check_systemd_service():
    section("CHECK 4 — Systemd Backdoor Service Status")
    if platform.system() != "Linux":
        print(f"  {YEL}[SKIP]{RESET}       Non-Linux system — skipping systemd check")
        return

    out = run(["systemctl", "--user", "is-active", "sysmon"])
    if out in ("active", "activating"):
        flag("CRITICAL", "SYSTEMD",
             f"sysmon.service is ACTIVE — backdoor is running right now!")
    elif out == "enabled":
        flag("CRITICAL", "SYSTEMD",
             "sysmon.service is ENABLED — will start on next login")
    else:
        ok(f"sysmon.service not active (status: {out or 'not found'})")

# ── Check 5: Suspicious running processes ────────────────────────────────────
def check_processes():
    section("CHECK 5 — Suspicious Running Processes")
    suspicious = ["sysmon.py", "litellm_init", "teamPCP"]

    out = run(["ps", "aux"])
    hits = []
    for line in out.splitlines():
        for keyword in suspicious:
            if keyword.lower() in line.lower():
                hits.append(line)

    if hits:
        for h in hits:
            flag("CRITICAL", "PROCESS", f"Suspicious process: {h[:120]}")
    else:
        ok("No suspicious processes matching known IoCs found")

# ── Check 6: Environment variable exposure ───────────────────────────────────
def check_env_vars():
    section("CHECK 6 — Sensitive Environment Variables at Risk")
    HIGH_VALUE_VARS = [
        # Cloud providers
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
        "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CLOUD_PROJECT",
        "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID",
        # AI/LLM API keys
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "COHERE_API_KEY",
        "GEMINI_API_KEY", "HUGGINGFACE_API_KEY", "MISTRAL_API_KEY",
        # Kubernetes
        "KUBECONFIG", "K8S_TOKEN", "KUBERNETES_SERVICE_ACCOUNT_TOKEN",
        # General
        "GITHUB_TOKEN", "GITLAB_TOKEN", "DATABASE_URL", "DB_PASSWORD",
        "SECRET_KEY", "JWT_SECRET", "STRIPE_SECRET_KEY",
        "LITELLM_MASTER_KEY", "LITELLM_PROXY_API_KEY",
    ]

    exposed = []
    for var in HIGH_VALUE_VARS:
        if os.environ.get(var):
            exposed.append(var)

    if exposed:
        flag("WARNING", "ENV_VARS",
             f"These high-value env vars were set in this environment:")
        for v in exposed:
            print(f"    {YEL}  → {v}{RESET}  (value hidden for safety)")
        flag("WARNING", "ENV_VARS",
             "If litellm 1.82.7/8 ran in this env, ROTATE these credentials NOW")
    else:
        ok("No sensitive env vars detected in current environment")

# ── Check 7: Cloud credential files ──────────────────────────────────────────
def check_credential_files():
    section("CHECK 7 — Cloud & Config Credential Files")
    cred_paths = [
        ("~/.aws/credentials",           "WARNING", "AWS credentials file"),
        ("~/.aws/config",                "INFO",    "AWS config file"),
        ("~/.config/gcloud/",            "WARNING", "GCloud credentials directory"),
        ("~/.kube/config",               "WARNING", "Kubernetes config (tokens inside)"),
        ("~/.docker/config.json",        "WARNING", "Docker registry auth"),
        ("~/.gitconfig",                 "INFO",    "Git config (may contain tokens)"),
        ("~/.npmrc",                     "WARNING", "NPM token file"),
        ("~/.pypirc",                    "WARNING", "PyPI credentials file"),
    ]

    exposed_creds = []
    for path_str, severity, desc in cred_paths:
        p = Path(path_str).expanduser()
        if p.exists():
            exposed_creds.append((severity, desc, str(p)))
            flag(severity, "CRED_FILE", f"{desc} exists: {p}")

    if not exposed_creds:
        ok("No common credential files found in home directory")
    else:
        print(f"\n  {YEL}→ If litellm 1.82.7/8 ever ran on this machine, "
              f"rotate ALL credentials in the above files{RESET}")

# ── Check 8: Docker images ────────────────────────────────────────────────────
def check_docker():
    section("CHECK 8 — Docker Images Containing LiteLLM")
    if not shutil.which("docker"):
        print(f"  {YEL}[SKIP]{RESET}       Docker not found on this system")
        return

    out = run(["docker", "images", "--format",
               "{{.Repository}}:{{.Tag}} {{.ID}} {{.CreatedAt}}"])
    if not out:
        ok("No Docker images found (or Docker daemon not running)")
        return

    hits = [line for line in out.splitlines()
            if "litellm" in line.lower()]
    if hits:
        for h in hits:
            flag("WARNING", "DOCKER",
                 f"LiteLLM Docker image found — inspect for bad version: {h}")
        print(f"\n  {YEL}  Run: docker inspect <image> | grep -i litellm{RESET}")
        print(f"  {YEL}  Run: docker run --rm <image> pip show litellm{RESET}")
    else:
        ok("No LiteLLM Docker images detected")

# ── Check 9: pip audit / package integrity ────────────────────────────────────
def check_pip_audit():
    section("CHECK 9 — pip-audit for Vulnerable Packages")
    if shutil.which("pip-audit"):
        print(f"  Running pip-audit (this may take a moment)...")
        out = run(["pip-audit", "--vulnerability-service", "pypi",
                   "-r", "/dev/stdin"],
                  shell=False)
        # simpler: just run against installed
        out = run(["pip-audit"])
        if "litellm" in out.lower():
            flag("WARNING", "PIP_AUDIT", f"pip-audit flagged litellm: {out[:300]}")
        elif out:
            ok("pip-audit completed — no litellm issues flagged")
        else:
            ok("pip-audit ran but produced no output")
    else:
        print(f"  {YEL}[INFO]{RESET}       pip-audit not installed. "
              f"Install with: pip install pip-audit")

# ── Check 10: Git log / CI pipeline ──────────────────────────────────────────
def check_cicd_exposure():
    section("CHECK 10 — CI/CD & Build Pipeline Exposure")
    cicd_files = [
        ".github/workflows",
        ".gitlab-ci.yml",
        "Jenkinsfile",
        ".circleci/config.yml",
        "bitbucket-pipelines.yml",
        "azure-pipelines.yml",
    ]
    found_cicd = []
    cwd = Path.cwd()
    for f in cicd_files:
        p = cwd / f
        if p.exists():
            found_cicd.append(str(p))

    if found_cicd:
        for f in found_cicd:
            flag("WARNING", "CICD",
                 f"CI/CD config found: {f} — check if litellm was installed unpinned here")
        print(f"\n  {YEL}  Search your pipelines for: pip install litellm{RESET}")
        print(f"  {YEL}  If found without ==version, your CI ran on March 24 may be compromised{RESET}")
    else:
        ok("No CI/CD pipeline files found in current directory")

# ── Summary & Remediation ─────────────────────────────────────────────────────
def print_summary():
    section("SUMMARY & REMEDIATION GUIDE")

    criticals = [f for f in findings if f["severity"] == "CRITICAL"]
    warnings  = [f for f in findings if f["severity"] == "WARNING"]

    print(f"  {BOLD}Results: {RED}{len(criticals)} CRITICAL{RESET}  "
          f"{YEL}{len(warnings)} WARNING{RESET}  "
          f"{len(findings) - len(criticals) - len(warnings)} INFO\n")

    if criticals:
        print(f"{RED}{BOLD}  ██ SYSTEM COMPROMISED — IMMEDIATE ACTION REQUIRED ██{RESET}\n")
        print(f"  {BOLD}CRITICAL STEPS (do these NOW):{RESET}")
        print(f"""
  1. ISOLATE THE MACHINE — disconnect from network if possible
  2. ROTATE ALL CREDENTIALS immediately:
       • AWS: aws iam create-access-key / rotate in IAM console
       • GCP: revoke service account keys in GCP Console
       • Azure: rotate client secrets in Azure AD
       • OpenAI/Anthropic/other LLM keys: rotate in provider dashboard
       • GitHub/GitLab tokens: Settings → Tokens → Revoke
       • Kubernetes: rotate ServiceAccount tokens
       • Database passwords: rotate via DB admin
  3. REMOVE MALICIOUS FILES:
       rm ~/.config/sysmon/sysmon.py
       rm ~/.config/systemd/user/sysmon.service
       systemctl --user disable sysmon
       systemctl --user stop sysmon
  4. REMOVE MALICIOUS PACKAGE:
       pip uninstall litellm -y
       pip install litellm==1.82.6   # or latest safe version
  5. REMOVE .pth FILE from site-packages (listed above)
  6. AUDIT LOGS for any outbound connections to unknown IPs
       (check your firewall, cloud VPC flow logs, etc.)
  7. CHECK KUBERNETES for unauthorized workloads / RBAC changes
       kubectl get pods --all-namespaces
       kubectl get clusterrolebindings
  8. REPORT to your security team / CISO immediately
""")
    elif warnings:
        print(f"{YEL}{BOLD}  ⚠ POTENTIAL RISK — Review warnings above{RESET}\n")
        print(f"  {BOLD}RECOMMENDED STEPS:{RESET}")
        print(f"""
  1. Verify litellm was NOT installed as 1.82.7 or 1.82.8 in your environment
  2. Check CI/CD pipeline logs for March 24, 2026 runs
  3. Proactively rotate any LLM API keys and cloud creds as a precaution
  4. Pin litellm to a safe version: pip install litellm==1.82.6
  5. Enable dependency pinning and hash verification in all pipelines
""")
    else:
        print(f"{GRN}{BOLD}  ✓ No indicators of compromise found on this system{RESET}\n")
        print(f"  {BOLD}PREVENTIVE STEPS:{RESET}")
        print(f"""
  1. Pin litellm version: pip install litellm>=1.82.9  (avoid 1.82.7 and 1.82.8)
  2. Use pip-audit or Dependabot for continuous dependency monitoring
  3. Enable OIDC/keyless auth in CI/CD (avoid storing long-lived credentials)
  4. Rotate LLM API keys periodically as good hygiene
""")

    print(f"  {BOLD}SAFE LITELLM VERSIONS:{RESET}")
    print(f"    ✗ 1.82.7 — MALICIOUS (do not use)")
    print(f"    ✗ 1.82.8 — MALICIOUS (do not use)")
    print(f"    ✓ 1.82.6 — Last known clean version before attack")
    print(f"    ✓ 1.82.9+ — Safe (published after attack window)")

    print(f"\n  {BOLD}SAVE THIS REPORT:{RESET}")
    report_path = Path.cwd() / f"litellm_impact_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    report = {
        "scan_time": datetime.now().isoformat(),
        "hostname": platform.node(),
        "os": platform.platform(),
        "python": sys.version,
        "findings": findings,
        "critical_count": len(criticals),
        "warning_count": len(warnings),
    }
    try:
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"  JSON report saved → {report_path}")
    except Exception as e:
        print(f"  Could not save report: {e}")

    print(f"\n  {BOLD}SOURCES & REFERENCES:{RESET}")
    print("  • LiteLLM official security update: https://docs.litellm.ai/blog/security-update-march-2026")
    print("  • Trend Micro analysis: https://www.trendmicro.com/en_us/research/26/c/inside-litellm-supply-chain-compromise.html")
    print("  • Kaspersky write-up: https://www.kaspersky.com/blog/critical-supply-chain-attack-trivy-litellm-checkmarx-teampcp/55510/")
    print()

# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    banner()
    print(f"  Scan started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Host         : {platform.node()}  |  OS: {platform.system()} {platform.release()}")
    print(f"  Python       : {sys.version.split()[0]}")
    # Log file path is known via the TeeLogger set up before main() is called
    tee_path = getattr(sys.stdout, "_log_path", None)
    if tee_path:
        print(f"  Log file     : {Path(tee_path).resolve()}")

    check_litellm_version()
    check_pth_file()
    check_persistence_files()
    check_systemd_service()
    check_processes()
    check_env_vars()
    check_credential_files()
    check_docker()
    check_pip_audit()
    check_cicd_exposure()
    print_summary()

if __name__ == "__main__":
    log_path, tee = setup_logger()
    try:
        main()
    finally:
        tee.close()
        # Print to real terminal (after tee is closed) so the path is visible
        print(f"\n  Terminal output saved → {log_path.resolve()}", file=sys.__stdout__)
