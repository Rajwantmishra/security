#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   LiteLLM Supply Chain Attack — Databricks Impact Checker                  ║
║   Attack Date : March 24, 2026  |  Bad Versions: 1.82.7 and 1.82.8        ║
║   Author      : Raj (rajwantmishra@gmail.com)                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  HOW TO RUN IN DATABRICKS:                                                 ║
║                                                                            ║
║  Option A — Databricks Notebook (recommended):                             ║
║    1. Create a new Python notebook                                         ║
║    2. In cell 1, paste this entire script                                  ║
║    3. Run the cell — output appears inline                                 ║
║                                                                            ║
║  Option B — Databricks Web Terminal:                                       ║
║    1. Compute → [cluster] → Apps → Web Terminal                            ║
║    2. Upload this file: databricks fs cp ./databricks_litellm_checker.py   ║
║                          dbfs:/tmp/databricks_litellm_checker.py           ║
║    3. python3 /dbfs/tmp/databricks_litellm_checker.py                      ║
║                                                                            ║
║  Option C — %sh magic in a notebook cell:                                  ║
║    %sh python3 /path/to/databricks_litellm_checker.py                      ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import json
import glob
import platform
import subprocess
import socket
from pathlib import Path
from datetime import datetime

# ── Output helpers (works in notebook + terminal) ────────────────────────────
FINDINGS = []

def title(msg):
    sep = "═" * 70
    print(f"\n{sep}")
    print(f"  {msg}")
    print(sep)

def section(msg):
    print(f"\n{'─'*70}")
    print(f"  CHECK: {msg}")
    print(f"{'─'*70}")

def critical(category, detail):
    FINDINGS.append({"severity": "CRITICAL", "category": category, "detail": detail})
    print(f"  [CRITICAL] {detail}")

def warning(category, detail):
    FINDINGS.append({"severity": "WARNING", "category": category, "detail": detail})
    print(f"  [WARNING]  {detail}")

def info(category, detail):
    FINDINGS.append({"severity": "INFO", "category": category, "detail": detail})
    print(f"  [INFO]     {detail}")

def ok(msg):
    print(f"  [OK]       {msg}")

def run_cmd(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return "", str(e)

# ── Detect Databricks environment ────────────────────────────────────────────
def detect_environment():
    section("Environment Detection")
    env_type = "generic"

    # Databricks-specific indicators
    db_indicators = {
        "DATABRICKS_RUNTIME_VERSION": os.environ.get("DATABRICKS_RUNTIME_VERSION"),
        "DB_HOME":                    os.environ.get("DB_HOME"),
        "SPARK_HOME":                 os.environ.get("SPARK_HOME"),
        "DATABRICKS_HOST":            os.environ.get("DATABRICKS_HOST"),
        "DB_CLUSTER_ID":              os.environ.get("DB_CLUSTER_ID"),
        "DB_IS_DRIVER":               os.environ.get("DB_IS_DRIVER"),
    }

    detected = {k: v for k, v in db_indicators.items() if v}
    if detected:
        env_type = "databricks"
        print(f"  Running on DATABRICKS cluster")
        for k, v in detected.items():
            if "token" not in k.lower() and "secret" not in k.lower():
                print(f"    {k} = {v}")
    else:
        print(f"  Running on generic Linux/Python environment")

    print(f"  Hostname  : {socket.gethostname()}")
    print(f"  Python    : {sys.version.split()[0]}")
    print(f"  OS        : {platform.platform()}")
    return env_type


# ── Check 1: LiteLLM version ─────────────────────────────────────────────────
def check_litellm_version():
    section("LiteLLM Version Check")
    BAD = {"1.82.7", "1.82.8"}

    # Method 1: pip show
    out, _ = run_cmd(["pip", "show", "litellm"])
    version = None
    for line in out.splitlines():
        if line.lower().startswith("version"):
            version = line.split(":", 1)[-1].strip()
            break

    # Method 2: importlib
    if not version:
        try:
            import importlib.metadata
            version = importlib.metadata.version("litellm")
        except Exception:
            pass

    # Method 3: direct import
    if not version:
        try:
            import litellm
            version = getattr(litellm, "__version__", None)
        except Exception:
            pass

    if version:
        if version in BAD:
            critical("VERSION",
                     f"LiteLLM {version} INSTALLED — this is the MALICIOUS version!")
        elif version < "1.82.7":
            ok(f"LiteLLM {version} installed — predates attack window (safe)")
        else:
            ok(f"LiteLLM {version} installed — not a known bad version")
    else:
        ok("LiteLLM not found in this Python environment")

    # Check all pip envs on the node
    out2, _ = run_cmd(["pip", "list", "--format=columns"])
    for line in out2.splitlines():
        if "litellm" in line.lower():
            print(f"  pip list entry: {line.strip()}")


# ── Check 2: Malicious .pth file ─────────────────────────────────────────────
def check_pth_file():
    section("Malicious .pth File (litellm_init.pth)")

    # Collect all site-packages
    dirs = set()
    try:
        import site
        dirs.update(site.getsitepackages())
        dirs.add(site.getusersitepackages())
    except Exception:
        pass

    # Databricks-specific Python paths
    extra = [
        "/databricks/python3/lib",
        "/databricks/python/lib",
        "/usr/lib/python3",
        "/usr/local/lib",
        str(Path.home() / ".local" / "lib"),
    ]
    for root in extra:
        for sp in Path(root).rglob("site-packages") if Path(root).exists() else []:
            dirs.add(str(sp))

    # Also brute-force search
    out, _ = run_cmd(["find", "/", "-name", "litellm_init.pth",
                      "-not", "-path", "*/proc/*", "2>/dev/null"])
    if out:
        for line in out.splitlines():
            if line.strip():
                critical("PTH_FILE",
                         f"FOUND litellm_init.pth at: {line.strip()}")
                critical("PTH_FILE",
                         "This file runs on EVERY Python startup — "
                         "system is FULLY COMPROMISED")
                try:
                    content = Path(line.strip()).read_text(errors="replace")[:400]
                    print(f"\n  File content preview:\n  {content}\n")
                except Exception:
                    pass
        return

    # Check site-packages explicitly
    found = False
    for sp in dirs:
        p = Path(sp) / "litellm_init.pth"
        if p.exists():
            found = True
            critical("PTH_FILE", f"FOUND: {p}")

    if not found:
        # One more: find via Python
        out2, _ = run_cmd(["python3", "-c",
                           "import site; [print(s) for s in site.getsitepackages()]"])
        for sp_dir in out2.splitlines():
            p = Path(sp_dir.strip()) / "litellm_init.pth"
            if p.exists():
                found = True
                critical("PTH_FILE", f"FOUND: {p}")

    if not found:
        ok("litellm_init.pth NOT found")


# ── Check 3: Backdoor persistence files ──────────────────────────────────────
def check_persistence_files():
    section("Backdoor Persistence Files")

    iocs = [
        ("~/.config/sysmon/sysmon.py",            "CRITICAL", "Backdoor RCE script"),
        ("~/.config/systemd/user/sysmon.service", "CRITICAL", "Systemd persistence unit"),
        ("~/.config/sysmon/",                     "WARNING",  "Sysmon config directory"),
    ]

    for path_str, severity, label in iocs:
        p = Path(path_str).expanduser()
        if p.exists():
            if severity == "CRITICAL":
                critical("PERSISTENCE", f"FOUND — {label}: {p}")
            else:
                warning("PERSISTENCE", f"FOUND — {label}: {p}")
            if p.is_file():
                try:
                    snippet = p.read_text(errors="replace")[:300]
                    print(f"  Content: {snippet[:200]}...")
                except Exception:
                    pass
        else:
            ok(f"Not present: {p}")

    # Extra: check /root paths (driver node may be root)
    for path_str, severity, label in iocs:
        root_path = path_str.replace("~", "/root")
        p = Path(root_path)
        if p.exists() and p != Path(path_str).expanduser():
            if severity == "CRITICAL":
                critical("PERSISTENCE", f"FOUND at root path — {label}: {p}")
            else:
                warning("PERSISTENCE", f"FOUND at root path: {p}")


# ── Check 4: Sensitive env vars exposed ──────────────────────────────────────
def check_env_vars():
    section("Sensitive Environment Variables")

    HIGH_VALUE = [
        # Databricks-specific
        "DATABRICKS_TOKEN", "DATABRICKS_HOST",
        "DB_API_TOKEN", "DATABRICKS_AAD_TOKEN",
        # Cloud
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID",
        # LLM APIs
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "COHERE_API_KEY",
        "GEMINI_API_KEY", "MISTRAL_API_KEY", "HUGGINGFACE_API_KEY",
        # Storage / DB
        "STORAGE_ACCOUNT_KEY", "DATABASE_URL", "DB_PASSWORD",
        "AZURE_STORAGE_CONNECTION_STRING",
        # Generic secrets
        "SECRET_KEY", "JWT_SECRET", "LITELLM_MASTER_KEY",
        "LITELLM_PROXY_API_KEY", "GITHUB_TOKEN",
    ]

    exposed = [v for v in HIGH_VALUE if os.environ.get(v)]

    if exposed:
        warning("ENV_VARS",
                f"{len(exposed)} high-value env var(s) present in this environment:")
        for v in exposed:
            val = os.environ.get(v, "")
            masked = val[:4] + "****" + val[-2:] if len(val) > 8 else "****"
            print(f"    → {v}  =  {masked}")
        warning("ENV_VARS",
                "If litellm 1.82.7 or 1.82.8 ever ran on this cluster, "
                "ROTATE all of the above credentials immediately")
    else:
        ok("No high-value env vars detected in current cluster environment")


# ── Check 5: Databricks secrets scope ────────────────────────────────────────
def check_databricks_secrets():
    section("Databricks Secret Scopes (dbutils)")
    try:
        # dbutils is available in Databricks notebooks
        import IPython
        ip = IPython.get_ipython()
        if ip is None:
            raise ImportError("Not in notebook")

        # Try to get dbutils
        dbutils = ip.user_ns.get("dbutils")
        if dbutils is None:
            print("  dbutils not available — run this check from a Databricks notebook")
            return

        scopes = dbutils.secrets.listScopes()
        if scopes:
            warning("SECRETS",
                    f"Found {len(scopes)} secret scope(s) — "
                    f"rotate secrets if cluster was compromised:")
            for s in scopes:
                keys = dbutils.secrets.list(s.name)
                print(f"    Scope: {s.name}")
                for k in keys:
                    print(f"      → {k.key}")
        else:
            ok("No Databricks secret scopes found")

    except ImportError:
        info("SECRETS",
             "dbutils not available — run from a Databricks notebook to check secrets")
    except Exception as e:
        info("SECRETS", f"Could not check secret scopes: {e}")


# ── Check 6: Cluster init scripts ────────────────────────────────────────────
def check_init_scripts():
    section("Cluster Init Scripts")

    init_dirs = [
        "/databricks/init_scripts",
        "/databricks/init",
        str(Path.home() / "init_scripts"),
        "/dbfs/databricks/init_scripts",
    ]

    found_any = False
    for d in init_dirs:
        p = Path(d)
        if p.exists():
            scripts = list(p.rglob("*.sh")) + list(p.rglob("*.py"))
            for script in scripts:
                found_any = True
                try:
                    content = script.read_text(errors="replace")
                    if "litellm" in content.lower():
                        if "1.82.7" in content or "1.82.8" in content:
                            critical("INIT_SCRIPT",
                                     f"Init script installs MALICIOUS litellm: {script}")
                        elif "==" not in content and "litellm" in content:
                            warning("INIT_SCRIPT",
                                    f"Init script installs unpinned litellm: {script}")
                        else:
                            info("INIT_SCRIPT",
                                 f"Init script references litellm: {script}")
                except Exception:
                    pass

    if not found_any:
        ok("No init scripts found in known Databricks directories")


# ── Check 7: DBFS for malicious files ────────────────────────────────────────
def check_dbfs():
    section("DBFS Scan for Malicious Files")

    dbfs_paths = [
        "/dbfs/tmp/litellm_init.pth",
        "/dbfs/tmp/sysmon.py",
        "/dbfs/databricks/init_scripts/litellm_init.pth",
    ]

    found = False
    for path in dbfs_paths:
        if Path(path).exists():
            found = True
            critical("DBFS", f"Suspicious file found on DBFS: {path}")

    # Also check via dbfs ls if available
    out, _ = run_cmd(["dbfs", "ls", "dbfs:/tmp/"])
    if out:
        for line in out.splitlines():
            if "litellm_init" in line or "sysmon" in line:
                found = True
                critical("DBFS", f"Suspicious DBFS file: {line.strip()}")

    if not found:
        ok("No malicious files detected on DBFS")


# ── Check 8: Running processes ────────────────────────────────────────────────
def check_processes():
    section("Suspicious Running Processes")

    out, _ = run_cmd(["ps", "aux"])
    hits = [line for line in out.splitlines()
            if any(kw in line.lower()
                   for kw in ["sysmon.py", "litellm_init", "teampcp"])]

    if hits:
        for h in hits:
            critical("PROCESS", f"Suspicious process: {h[:120]}")
    else:
        ok("No suspicious processes found")


# ── Check 9: Network connections ─────────────────────────────────────────────
def check_network():
    section("Suspicious Outbound Network Connections")

    out, _ = run_cmd(["ss", "-tunp"])
    if not out:
        out, _ = run_cmd(["netstat", "-tunp"])

    suspicious_ports = [4444, 1337, 31337, 8888, 9999]  # common backdoor ports
    hits = []
    for line in out.splitlines():
        for port in suspicious_ports:
            if f":{port}" in line and "ESTABLISHED" in line:
                hits.append(line)

    if hits:
        for h in hits:
            warning("NETWORK", f"Suspicious connection: {h[:100]}")
    else:
        ok("No connections on known backdoor ports detected")


# ── Check 10: Requirements / dependency files ─────────────────────────────────
def check_requirements():
    section("Requirements Files — Version Pinning")

    search_dirs = [
        "/databricks/driver",
        "/Workspace",
        str(Path.home()),
        "/dbfs/FileStore",
        ".",
    ]

    req_files = []
    for d in search_dirs:
        if Path(d).exists():
            for pattern in ["requirements*.txt", "setup.py", "pyproject.toml",
                            "Pipfile", "environment.yml"]:
                req_files.extend(Path(d).rglob(pattern))

    found_issue = False
    for rf in req_files[:20]:  # cap at 20 to avoid huge output
        try:
            content = rf.read_text(errors="replace")
            if "litellm" in content.lower():
                if "1.82.7" in content or "1.82.8" in content:
                    critical("REQUIREMENTS",
                             f"Bad version pinned in {rf}")
                    found_issue = True
                elif "litellm==" not in content.lower():
                    warning("REQUIREMENTS",
                            f"Unpinned litellm in {rf} — upgrade risk")
                    found_issue = True
                else:
                    ok(f"litellm pinned in {rf}")
        except Exception:
            pass

    if not found_issue and not req_files:
        ok("No requirements files found to scan")


# ── Summary & remediation ─────────────────────────────────────────────────────
def print_summary():
    title("SCAN SUMMARY & REMEDIATION")

    criticals = [f for f in FINDINGS if f["severity"] == "CRITICAL"]
    warnings  = [f for f in FINDINGS if f["severity"] == "WARNING"]
    infos     = [f for f in FINDINGS if f["severity"] == "INFO"]

    print(f"\n  CRITICAL : {len(criticals)}")
    print(f"  WARNING  : {len(warnings)}")
    print(f"  INFO     : {len(infos)}")
    print(f"  SCAN TIME: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  HOST     : {socket.gethostname()}")

    if criticals:
        print("""
  ══════════════════════════════════════════════════════════════════
  CLUSTER COMPROMISED — ACT IMMEDIATELY
  ══════════════════════════════════════════════════════════════════

  1. TERMINATE this cluster right now (do NOT just stop it)
       Databricks → Compute → [cluster] → Terminate

  2. ROTATE Databricks credentials:
       • Personal access tokens:
         User Settings → Access Tokens → Revoke all
       • Service principal secrets (Azure AD / Entra ID)
       • All Databricks secret scopes used by this cluster

  3. ROTATE cloud credentials attached to this cluster:
       • AWS: IAM Console → rotate or delete access keys
       • Azure: Azure AD → App Registrations → rotate client secrets
       • GCP: IAM Console → rotate service account keys

  4. ROTATE all LLM API keys that were in env vars:
       • OpenAI, Anthropic, Cohere, Gemini, etc.

  5. AUDIT Databricks audit logs:
       Admin Console → Audit Logs → filter by March 24, 2026
       Look for: unusual secret reads, job runs, cluster creates

  6. AUDIT cloud provider logs:
       • AWS CloudTrail, GCP Audit Logs, Azure Activity Log
       • Look for API calls from the compromised cluster on/after March 24

  7. REMOVE litellm from the cluster and reinstall safe version:
       pip uninstall litellm -y
       pip install litellm==1.82.6

  8. NOTIFY your security team / CISO immediately
""")
    elif warnings:
        print("""
  ══════════════════════════════════════════════════════════════════
  POTENTIAL RISK — Review warnings above
  ══════════════════════════════════════════════════════════════════

  1. Verify litellm version was NOT 1.82.7 or 1.82.8 on this cluster
  2. Check cluster history for any runs on March 24, 2026
  3. Rotate Databricks tokens and LLM API keys as a precaution
  4. Pin litellm to a safe version in all init scripts and requirements
  5. Enable pip-audit in your CI/CD and cluster init pipelines
""")
    else:
        print("""
  ══════════════════════════════════════════════════════════════════
  NO INDICATORS OF COMPROMISE FOUND ON THIS CLUSTER
  ══════════════════════════════════════════════════════════════════

  Preventive actions:
  1. Pin litellm: pip install "litellm>=1.82.9"  (avoid 1.82.7 and 1.82.8)
  2. Add pip-audit to your cluster init scripts
  3. Use Databricks secret scopes (never hardcode keys in notebooks)
  4. Enable Databricks audit logging
  5. Rotate LLM API keys periodically
""")

    # Save JSON report to DBFS if possible
    report = {
        "scan_time": datetime.now().isoformat(),
        "hostname": socket.gethostname(),
        "os": platform.platform(),
        "python": sys.version,
        "findings": FINDINGS,
        "critical_count": len(criticals),
        "warning_count": len(warnings),
        "scanned_by": "Raj | rajwantmishra@gmail.com",
    }
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Try DBFS first, fall back to local
    for out_path in [f"/dbfs/tmp/litellm_scan_{ts}.json",
                     f"/tmp/litellm_scan_{ts}.json",
                     f"./litellm_scan_{ts}.json"]:
        try:
            Path(out_path).parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w") as fh:
                json.dump(report, fh, indent=2)
            print(f"  JSON report saved → {out_path}")
            break
        except Exception:
            continue

    print("""
  ─────────────────────────────────────────────────────────────────
  SAFE LITELLM VERSIONS:
    ✗  1.82.7 — MALICIOUS
    ✗  1.82.8 — MALICIOUS
    ✓  1.82.6 — Last safe version before attack
    ✓  1.82.9+ — Safe (post-attack)

  SOURCES:
    https://docs.litellm.ai/blog/security-update-march-2026
    https://www.trendmicro.com/en_us/research/26/c/inside-litellm-supply-chain-compromise.html
    https://www.kaspersky.com/blog/critical-supply-chain-attack-trivy-litellm-checkmarx-teampcp/55510/
  ─────────────────────────────────────────────────────────────────
  Prepared by : Raj  |  rajwantmishra@gmail.com
  Scan Date   : {date}
  ─────────────────────────────────────────────────────────────────
""".format(date=datetime.now().strftime("%Y-%m-%d %H:%M:%S")))


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    title("LiteLLM Supply Chain Attack — Databricks Impact Checker")
    print("  Attack Date  : March 24, 2026")
    print("  Bad Versions : 1.82.7 and 1.82.8")
    print("  Prepared by  : Raj (rajwantmishra@gmail.com)")

    env_type = detect_environment()
    check_litellm_version()
    check_pth_file()
    check_persistence_files()
    check_env_vars()
    check_databricks_secrets()
    check_init_scripts()
    check_dbfs()
    check_processes()
    check_network()
    check_requirements()
    print_summary()


main()
