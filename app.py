#!/usr/bin/env python3
import os
import logging
from datetime import datetime
import pandas as pd
from tabulate import tabulate
from dotenv import load_dotenv

# Local modules
from tools.data_tools import correlate_data, tcp_scan_ports, load_escalation_config
from tools.analyzer import get_vulnerability_summary, get_critical_assets, get_asset_summary

# ----------------------------------------------------
# Environment + Logging
# ----------------------------------------------------
load_dotenv()
logging.basicConfig(filename="agent.log", level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")

MODEL = "gpt-4o-mini"
print("──────────────────────────────────────────────")
print(f"🤖  Model: \033[96m{MODEL}\033[0m")
print("💬  LLM connectivity check is optional in this CLI-only build.")
print("──────────────────────────────────────────────\n")

# ----------------------------------------------------
# Data Loading + Auto Reload
# ----------------------------------------------------
def safe_list_data_files():
    try:
        return [f for f in os.listdir("data") if f.endswith(".csv")]
    except FileNotFoundError:
        os.makedirs("data", exist_ok=True)
        return []

df = correlate_data()
# normalize ip naming
if "ip_address" in df.columns and "ip" not in df.columns:
    df.rename(columns={"ip_address": "ip"}, inplace=True)

_last_modified = {f: os.path.getmtime(os.path.join("data", f)) for f in safe_list_data_files()}

def refresh_data_if_changed():
    global df, _last_modified
    changed = False
    for f in safe_list_data_files():
        path = os.path.join("data", f)
        try:
            mtime = os.path.getmtime(path)
        except Exception:
            mtime = None
        if _last_modified.get(f) != mtime:
            _last_modified[f] = mtime
            changed = True
    if changed:
        print("🔄 Detected data changes, reloading...")
        df = correlate_data()
        if "ip_address" in df.columns and "ip" not in df.columns:
            df.rename(columns={"ip_address": "ip"}, inplace=True)
        print("✅ Data refreshed.\n")

# ----------------------------------------------------
# Helpers
# ----------------------------------------------------
def _colorize_severity(sev: str) -> str:
    s = str(sev).lower()
    if s == "critical": return f"\033[91m{sev}\033[0m"
    if s == "high": return f"\033[93m{sev}\033[0m"
    if s == "medium": return f"\033[33m{sev}\033[0m"
    if s == "low": return f"\033[94m{sev}\033[0m"
    if s in ("info", "informational"): return f"\033[90m{sev}\033[0m"
    return sev

def _maybe_export(query: str, filtered: pd.DataFrame, label: str) -> str:
    intent = any(w in query.lower() for w in ("export", "save", "csv", "write"))
    if not intent:
        return ""
    os.makedirs("output", exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    path = f"output/{label}_{len(filtered)}rows_{ts}.csv"
    filtered.to_csv(path, index=False)
    logging.info("Exported %d rows to %s", len(filtered), path)
    return f"\n\n💾 Exported \033[92m{len(filtered)}\033[0m rows to: \033[96m{path}\033[0m"

# ----------------------------------------------------
# Commands
# ----------------------------------------------------
def cmd_list_by_severity(query: str) -> str:
    """List vulnerabilities by one or more severities."""
    try:
        refresh_data_if_changed()
        if df.empty:
            return "No data loaded yet. Place CSVs in ./data and try again."

        keys = ["critical", "high", "medium", "low", "info", "informational"]
        requested = [k.capitalize() for k in keys if k in query.lower()]
        if not requested:
            return "Please specify severities (e.g., High, Critical, Medium, Low)."

        filtered = df[df["severity"].str.lower().isin([s.lower() for s in requested])]
        if filtered.empty:
            return f"No vulnerabilities found with severities: {', '.join(requested)}."

        # Sort
        sort_cols = ["severity"] + (["cvss_score"] if "cvss_score" in filtered.columns else [])
        filtered = filtered.sort_values(by=sort_cols, ascending=[True, False])

        disp = filtered.copy()
        if "severity" in disp.columns:
            disp["severity"] = disp["severity"].apply(_colorize_severity)

        # --- Build display columns (include IP always if exists) ---
        display_cols = []
        for col in ["asset_id", "ip", "cve_id", "severity", "cvss_score", "owner"]:
            if col in disp.columns:
                display_cols.append(col)
        if "escalation_reason" in disp.columns and disp["escalation_reason"].astype(str).str.len().sum() > 0:
            disp["escalation_reason"] = disp["escalation_reason"].apply(lambda x: (x[:120] + "...") if len(str(x)) > 120 else x)
            display_cols.append("escalation_reason")

        table = tabulate(disp[display_cols],
                         headers=[c.upper().replace("_", " ") for c in display_cols],
                         tablefmt="fancy_grid", showindex=False)
        result = f"Vulnerabilities with severities ({', '.join(requested)}):\n\n{table}"

        if "escalation_reason" in filtered.columns:
            num_esc = (filtered["escalation_reason"].astype(str).str.len() > 0).sum()
            if num_esc:
                result += f"\n\n⚠️ {num_esc} vulnerabilities escalated due to risky open ports."

        result += _maybe_export(query, filtered, f"vulns_{'_'.join(requested)}")
        return result

    except Exception as e:
        logging.exception("Error in cmd_list_by_severity: %s", e)
        return f"Error listing by severity: {e}"

def cmd_list_by_asset(query: str) -> str:
    """List vulnerabilities for a specific asset or IP."""
    try:
        refresh_data_if_changed()
        if df.empty:
            return "No data loaded yet. Place CSVs in ./data and try again."

        target = None
        ignore_words = {"show", "list", "export", "save", "csv", "write", "for", "with", "the", "and"}
        for tok in query.replace(",", " ").split():
            t = tok.strip().lower()
            if t in ignore_words:
                continue
            if "." in t or any(ch.isalnum() for ch in t):
                if t in {"high", "critical", "medium", "low", "info", "informational"}:
                    continue
                target = tok.strip()
                break

        if not target:
            return "Please include an asset name or IP (e.g., 'web01' or '10.0.0.10')."

        keys = ["critical", "high", "medium", "low", "info", "informational"]
        requested = [k.capitalize() for k in keys if k in query.lower()]

        mask = pd.Series([False] * len(df))
        if "asset_id" in df.columns:
            mask |= df["asset_id"].astype(str).str.contains(target, case=False, na=False)
        if "ip" in df.columns:
            mask |= df["ip"].astype(str).str.contains(target, case=False, na=False)

        filtered = df[mask]
        if filtered.empty:
            return f"No vulnerabilities found for '{target}'."

        if requested:
            filtered = filtered[filtered["severity"].str.lower().isin([s.lower() for s in requested])]
            if filtered.empty:
                return f"No vulnerabilities found for {target} with severities: {', '.join(requested)}."

        sort_cols = ["severity"] + (["cvss_score"] if "cvss_score" in filtered.columns else [])
        filtered = filtered.sort_values(by=sort_cols, ascending=[True, False])
        disp = filtered.copy()
        if "severity" in disp.columns:
            disp["severity"] = disp["severity"].apply(_colorize_severity)

        display_cols = []
        for col in ["asset_id", "ip", "cve_id", "severity", "cvss_score", "owner"]:
            if col in disp.columns:
                display_cols.append(col)
        if "escalation_reason" in disp.columns and disp["escalation_reason"].astype(str).str.len().sum() > 0:
            disp["escalation_reason"] = disp["escalation_reason"].apply(lambda x: (x[:120] + "...") if len(str(x)) > 120 else x)
            display_cols.append("escalation_reason")

        table = tabulate(disp[display_cols],
                         headers=[c.upper().replace("_", " ") for c in display_cols],
                         tablefmt="fancy_grid", showindex=False)
        result = f"Vulnerabilities for '{target}':\n\n{table}"

        if "escalation_reason" in filtered.columns:
            num_esc = (filtered["escalation_reason"].astype(str).str.len() > 0).sum()
            if num_esc:
                result += f"\n\n⚠️ {num_esc} vulnerabilities escalated due to risky open ports."

        label = f"vulns_{target}" if not requested else f"vulns_{target}_{'_'.join(requested)}"
        result += _maybe_export(query, filtered, label)
        return result

    except Exception as e:
        logging.exception("Error in cmd_list_by_asset: %s", e)
        return f"Error listing by asset: {e}"

def cmd_scan(query: str) -> str:
    """Active TCP port scan command."""
    try:
        toks = query.replace(",", " ").split()
        if len(toks) < 2:
            return "Usage: scan <ip> [port1 port2 ...] [timeout=SECONDS] [workers=N]"

        target = toks[1].strip()
        ports, timeout, workers = [], None, None
        for t in toks[2:]:
            if "=" in t:
                k, v = t.split("=", 1)
                if k.lower() == "timeout":
                    try: timeout = float(v)
                    except Exception: pass
                elif k.lower() == "workers":
                    try: workers = int(v)
                    except Exception: pass
            elif t.isdigit():
                ports.append(int(t))

        cfg = load_escalation_config() or {}
        if not ports:
            ports = cfg.get("non_standard_ports", [])
        if timeout is None:
            timeout = cfg.get("active_scan", {}).get("timeout_seconds", 0.5)
        if workers is None:
            workers = cfg.get("active_scan", {}).get("max_workers", 20)

        active_cfg = cfg.get("active_scan", {})
        enabled_by_config = bool(active_cfg.get("enabled", False))
        provided_ports_manually = len([t for t in toks[2:] if t.isdigit()]) > 0
        if not enabled_by_config and not provided_ports_manually:
            return ("Active scanning is disabled in config. Enable it by setting\n"
                    "`config/severity_rules.json` -> \"active_scan\": { \"enabled\": true }\n"
                    "or provide explicit ports on the command line (e.g. `scan 10.0.1.5 8080 8443`).")

        open_ports = tcp_scan_ports(target, ports, timeout=float(timeout), max_workers=int(workers))
        lines = [f"Scan results for {target} (timeout={timeout}s, workers={workers}):"]
        if not open_ports:
            lines.append("  No open ports detected among the tested ports.")
        else:
            lines.append(f"  Open ports: {', '.join(map(str, open_ports))}")
            risky = set(cfg.get("risky_ports", []))
            nonstd = set(cfg.get("non_standard_ports", []))
            hit_risky = sorted([p for p in open_ports if p in risky])
            hit_nonstd = sorted([p for p in open_ports if p in nonstd and p not in risky])
            if hit_risky:
                lines.append(f"  ⚠️ Found risky port(s) that may trigger immediate escalation: {', '.join(map(str, hit_risky))}")
            if hit_nonstd:
                lines.append(f"  ⚠️ Found non-standard port(s): {', '.join(map(str, hit_nonstd))} (suggest bumping severity by 1)")
        lines.append("\nNote: Only scan hosts you are authorized to test.")
        return "\n".join(lines)

    except Exception as e:
        logging.exception("Error in cmd_scan: %s", e)
        return f"Error running scan: {e}"

# ----------------------------------------------------
# CLI Help + Loop
# ----------------------------------------------------
HELP = """\
Commands:
  - list high|critical|medium|low [and ...] [export/save/csv]
  - show <asset_or_ip> [high|critical|...] [export/save/csv]
  - scan <ip> [port1 port2 ...] [timeout=SECONDS] [workers=N]   # active TCP connect scan (opt-in)
Examples:
  > list high and critical
  > show web01
  > show 10.0.1.5 high export
  > scan 10.0.1.5 8080 8443
"""

if __name__ == "__main__":
    print("✅ Vulnerability Agent ready! Type 'help' or 'exit'.\n")
    while True:
        try:
            q = input("🔎 > ").strip()
            if not q:
                continue
            if q.lower() in ("quit", "exit", "q"):
                print("👋 Bye!"); break
            if q.lower() in ("help", "?"):
                print(HELP); continue

            ql = q.lower().strip()
            if ql.startswith("scan "):
                print("\n" + cmd_scan(q) + "\n"); continue
            if any(s in ql for s in ("critical", "high", "medium", "low")) and "show" not in ql:
                print("\n" + cmd_list_by_severity(q) + "\n"); continue
            if ql.startswith("show ") or any("." in w for w in q.split()):
                print("\n" + cmd_list_by_asset(q) + "\n"); continue

            print("🤖 Try: 'list high and critical' or 'show web01' or 'scan 10.0.1.5'.\n")

        except KeyboardInterrupt:
            print("\n👋 Bye!"); break
        except Exception as e:
            logging.exception("CLI error: %s", e)
            print(f"❌ Error: {e}")