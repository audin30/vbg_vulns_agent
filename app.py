#!/usr/bin/env python3
import os
import re
import logging
from datetime import datetime
import pandas as pd
from tabulate import tabulate
from dotenv import load_dotenv

# Local modules
from tools.data_tools import correlate_data, tcp_scan_ports, load_escalation_config
from tools.analyzer import get_vulnerability_summary, get_critical_assets, get_asset_summary, correlate_with_firewall

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
# ANSI Helpers for Table Alignment
# ----------------------------------------------------
ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

def strip_ansi(text):
    """Remove ANSI escape codes."""
    return ANSI_ESCAPE.sub('', str(text))

def make_pretty_table(df, cols):
    """Render ANSI-aligned table manually to preserve color and spacing."""
    if df.empty or not cols:
        return "No data to display."

    safe_df = df.copy()
    for c in safe_df.columns:
        safe_df[c] = safe_df[c].apply(strip_ansi)

    # Compute column widths
    widths = {c: safe_df[c].astype(str).map(len).max() for c in cols}
    for c in cols:
        header_len = len(c.upper().replace("_", " "))
        if widths[c] < header_len:
            widths[c] = header_len

    # Build header
    header = " │ ".join(c.upper().replace("_", " ").ljust(widths[c]) for c in cols)
    sep = "─" * (len(header) + 4)
    lines = [sep, f"│ {header} │", sep]

    # Build rows
    for _, row in df.iterrows():
        row_str = " │ ".join(str(row[c]).ljust(widths[c]) if c in df.columns else "" for c in cols)
        lines.append(f"│ {row_str} │")

    lines.append(sep)
    return "\n".join(lines)

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
# Commands: List, Show, Scan, Correlate
# ----------------------------------------------------
def cmd_list_by_severity(query: str) -> str:
    """List vulnerabilities by severity."""
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

    filtered = filtered.sort_values(by=["severity", "cvss_score"], ascending=[True, False])
    disp = filtered.copy()
    disp["severity"] = disp["severity"].apply(_colorize_severity)

    display_cols = [c for c in ["asset_id", "ip", "cve_id", "severity", "cvss_score", "owner", "escalation_reason"] if c in disp.columns]
    table = make_pretty_table(disp, display_cols)
    result = f"Vulnerabilities with severities ({', '.join(requested)}):\n\n{table}"

    result += _maybe_export(query, filtered, f"vulns_{'_'.join(requested)}")
    return result


def cmd_list_by_asset(query: str) -> str:
    """List vulnerabilities for a specific asset or IP."""
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
            target = tok.strip()
            break

    if not target:
        return "Please include an asset name or IP (e.g., 'web01' or '10.0.0.10')."

    mask = pd.Series([False] * len(df))
    if "asset_id" in df.columns:
        mask |= df["asset_id"].astype(str).str.contains(target, case=False, na=False)
    if "ip" in df.columns:
        mask |= df["ip"].astype(str).str.contains(target, case=False, na=False)
    filtered = df[mask]
    if filtered.empty:
        return f"No vulnerabilities found for '{target}'."

    disp = filtered.copy()
    disp["severity"] = disp["severity"].apply(_colorize_severity)
    display_cols = [c for c in ["asset_id", "ip", "cve_id", "severity", "cvss_score", "owner", "escalation_reason"] if c in disp.columns]

    table = make_pretty_table(disp, display_cols)
    result = f"Vulnerabilities for '{target}':\n\n{table}"
    result += _maybe_export(query, filtered, f"vulns_{target}")
    return result


def cmd_correlate_firewall(query: str) -> str:
    """Correlate vulnerabilities with firewall rules and escalate severity."""
    refresh_data_if_changed()
    if df.empty:
        return "No vulnerability data found."

    fw_path = os.path.join("data", "firewall_rules.csv")
    if not os.path.exists(fw_path):
        return "⚠️ No firewall_rules.csv found in ./data"

    fw_df = pd.read_csv(fw_path)
    correlated = correlate_with_firewall(df, fw_df)
    if correlated.empty:
        return "No correlations found between vulnerabilities and firewall rules."

    correlated["effective_severity"] = correlated["effective_severity"].apply(_colorize_severity)

    display_cols = ["asset_id", "ip", "cve_id", "base_severity", "effective_severity", "firewall_ports", "firewall_escalation"]
    table = make_pretty_table(correlated, display_cols)
    result = f"🔐 Correlation Results (Firewall-Aware Severity):\n\n{table}"

    result += _maybe_export(query, correlated, "firewall_correlation")
    return result


# ----------------------------------------------------
# CLI Help + Loop
# ----------------------------------------------------
HELP = """\
Commands:
  - list high|critical|medium|low [export/save/csv]
  - show <asset_or_ip> [export/save/csv]
  - scan <ip> [port1 port2 ...]
  - correlate firewall [export/save/csv]
Examples:
  > list critical
  > show web01
  > correlate firewall
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

            ql = q.lower()
            if ql.startswith("correlate firewall"):
                print("\n" + cmd_correlate_firewall(q) + "\n"); continue
            if any(s in ql for s in ("critical", "high", "medium", "low")) and "show" not in ql:
                print("\n" + cmd_list_by_severity(q) + "\n"); continue
            if ql.startswith("show "):
                print("\n" + cmd_list_by_asset(q) + "\n"); continue

            print("🤖 Try: 'list high and critical', 'show web01', or 'correlate firewall'.\n")

        except KeyboardInterrupt:
            print("\n👋 Bye!"); break
        except Exception as e:
            logging.exception("CLI error: %s", e)
            print(f"❌ Error: {e}")