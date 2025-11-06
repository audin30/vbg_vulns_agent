import pandas as pd
import logging
import json
import os


# ----------------------------------------------------
# Load Config
# ----------------------------------------------------
def _load_escalation_config(path="config/severity_rules.json"):
    try:
        if not os.path.exists(path):
            return {
                "risky_ports": [22, 3389, 3306],
                "non_standard_ports": [23, 5900, 8080, 8443, 33060],
                "escalation_map": {
                    "Low": "Medium",
                    "Medium": "High",
                    "High": "Critical",
                    "Critical": "Critical"
                }
            }
        with open(path, "r") as f:
            return json.load(f)
    except Exception as e:
        logging.exception("Error loading escalation config: %s", e)
        return {}


# ----------------------------------------------------
# Vulnerability Summary
# ----------------------------------------------------
def get_vulnerability_summary(df: pd.DataFrame) -> str:
    """Generate a summary of vulnerabilities by severity."""
    if df.empty:
        return "No vulnerability data available."

    try:
        counts = df["severity"].value_counts().to_dict()
        total = len(df)
        parts = [f"{sev}: {count}" for sev, count in sorted(counts.items(), key=lambda x: x[0].lower())]
        return f"📊 Total Vulnerabilities: {total}\n" + "\n".join([f" - {p}" for p in parts])
    except Exception as e:
        logging.exception("Error generating vulnerability summary: %s", e)
        return "Error generating vulnerability summary."


# ----------------------------------------------------
# Critical Asset Summary
# ----------------------------------------------------
def get_critical_assets(df: pd.DataFrame, top_n: int = 10) -> pd.DataFrame:
    """Return top N assets with the most critical vulnerabilities."""
    if df.empty or "severity" not in df.columns:
        return pd.DataFrame()

    try:
        crit_df = df[df["severity"].str.lower() == "critical"]
        top_assets = (
            crit_df.groupby(["asset_id", "ip"])
            .size()
            .reset_index(name="critical_count")
            .sort_values(by="critical_count", ascending=False)
            .head(top_n)
        )
        return top_assets
    except Exception as e:
        logging.exception("Error getting critical assets: %s", e)
        return pd.DataFrame()


# ----------------------------------------------------
# Firewall-Aware Severity Correlation
# ----------------------------------------------------
def correlate_with_firewall(vuln_df: pd.DataFrame, fw_df: pd.DataFrame, config_path="config/severity_rules.json"):
    """
    Correlate vulnerabilities with firewall rules.
    If open non-standard or risky ports are allowed, bump criticality.
    Returns a new DataFrame with an added 'firewall_escalation' and 'effective_severity'.
    """
    try:
        cfg = _load_escalation_config(config_path)
        risky_ports = set(cfg.get("risky_ports", []))
        nonstd_ports = set(cfg.get("non_standard_ports", []))
        esc_map = cfg.get("escalation_map", {})

        if vuln_df.empty:
            return pd.DataFrame()

        # Normalize firewall columns
        if not fw_df.empty:
            fw_df.columns = fw_df.columns.str.lower()
            for col in ["asset_id", "port", "action"]:
                if col not in fw_df.columns:
                    logging.warning(f"Missing expected column in firewall data: {col}")
            fw_df["port"] = fw_df["port"].astype(str)
        else:
            fw_df = pd.DataFrame(columns=["asset_id", "port", "action"])

        results = []
        for _, row in vuln_df.iterrows():
            asset = row.get("asset_id", "")
            base_sev = str(row.get("severity", "")).capitalize()
            current_sev = base_sev
            reason = ""

            fw_open = fw_df[
                (fw_df["asset_id"].astype(str) == str(asset)) &
                (fw_df["action"].astype(str).str.lower() == "allow")
            ]

            if not fw_open.empty:
                try:
                    ports = [int(p) for p in fw_open["port"].tolist() if p.isdigit()]
                except Exception:
                    ports = []
            else:
                ports = []

            risky_found = [p for p in ports if p in risky_ports]
            nonstd_found = [p for p in ports if p in nonstd_ports]

            if risky_found or nonstd_found:
                mapped = esc_map.get(base_sev, base_sev)
                if mapped != base_sev:
                    current_sev = mapped
                    reason_parts = []
                    if risky_found:
                        reason_parts.append(f"risky ports {', '.join(map(str, risky_found))}")
                    if nonstd_found:
                        reason_parts.append(f"non-standard ports {', '.join(map(str, nonstd_found))}")
                    reason = f"Escalated from {base_sev} → {current_sev} due to open {', '.join(reason_parts)}."

            results.append({
                "asset_id": asset,
                "ip": row.get("ip", ""),
                "cve_id": row.get("cve_id", ""),
                "base_severity": base_sev,
                "effective_severity": current_sev,
                "firewall_ports": ", ".join(map(str, ports)) if ports else "",
                "firewall_escalation": reason
            })

        return pd.DataFrame(results)

    except Exception as e:
        logging.exception("Error correlating with firewall: %s", e)
        return pd.DataFrame()


# ----------------------------------------------------
# Asset-Level Summary
# ----------------------------------------------------
def get_asset_summary(df: pd.DataFrame, asset_id: str) -> str:
    """Produce a summary for a specific asset with escalation context."""
    if df.empty:
        return "No data available."
    if not asset_id:
        return "No asset ID specified."

    try:
        subset = df[df["asset_id"].astype(str).str.lower() == asset_id.lower()]
        if subset.empty:
            return f"No vulnerabilities found for asset '{asset_id}'."

        lines = [f"🔍 Asset Summary: {asset_id}", "-" * 60]
        for _, row in subset.iterrows():
            cve = row.get("cve_id", "N/A")
            sev = row.get("severity", "N/A")
            score = row.get("cvss_score", "")
            ip = row.get("ip", "")
            reason = row.get("escalation_reason", "")
            lines.append(f"• {cve} ({sev}, CVSS {score})  {(f'(IP: {ip})' if ip else '')}")
            if reason:
                lines.append(f"    ↳ Escalation: {reason}")
        return "\n".join(lines)
    except Exception as e:
        logging.exception("Error generating asset summary: %s", e)
        return f"Error generating asset summary for {asset_id}: {e}"