import os
import json
import socket
import pandas as pd
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed


# ----------------------------------------------------
# Load configuration
# ----------------------------------------------------
def load_escalation_config(path="config/severity_rules.json"):
    """Load escalation and scanning configuration."""
    try:
        if not os.path.exists(path):
            logging.warning("Config file not found, using defaults.")
            return {
                "risky_ports": [22, 3389, 3306],
                "non_standard_ports": [23, 5900, 8080, 8443, 33060],
                "active_scan": {"enabled": False, "timeout_seconds": 0.5, "max_workers": 30},
                "escalation_map": {"Low": "Medium", "Medium": "High", "High": "Critical", "Critical": "Critical"}
            }
        with open(path, "r") as f:
            return json.load(f)
    except Exception as e:
        logging.exception("Failed to load escalation config: %s", e)
        return {}


# ----------------------------------------------------
# Lightweight TCP connect scanner
# ----------------------------------------------------
def tcp_scan_ports(ip: str, ports: list, timeout: float = 0.5, max_workers: int = 20) -> list:
    """Perform a lightweight TCP connect scan (parallel). Returns list of open ports."""
    open_ports = []

    def _probe(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                res = s.connect_ex((ip, int(port)))
                return port if res == 0 else None
        except Exception:
            return None

    if not ports:
        return []

    ports = [int(p) for p in ports]
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_probe, p): p for p in ports}
        for fut in as_completed(futures):
            r = fut.result()
            if r:
                open_ports.append(int(r))
    return sorted(set(open_ports))


# ----------------------------------------------------
# Severity escalation logic
# ----------------------------------------------------
def _adjust_one(row, firewall_df, config):
    """
    Adjust severity based on:
      - Allowed risky ports from firewall rules
      - Optional active scan for non-standard ports
    """
    risky_ports = config.get("risky_ports", [])
    esc_map = config.get("escalation_map", {})
    original_sev = str(row.get("severity", "")).strip() or ""
    new_sev = original_sev
    reasons = []

    # --- Firewall-based escalation ---
    if not firewall_df.empty and all(c in firewall_df.columns for c in ("asset_id", "port", "action")):
        matches = firewall_df[
            (firewall_df["asset_id"].astype(str) == str(row.get("asset_id", ""))) &
            (firewall_df["action"].astype(str).str.lower() == "allow")
        ]
        try:
            open_ports_fw = [int(p) for p in matches["port"].tolist()]
        except Exception:
            open_ports_fw = []
        risky_open_fw = [p for p in open_ports_fw if p in risky_ports]
        if risky_open_fw:
            mapped = esc_map.get(original_sev, original_sev)
            if mapped != original_sev:
                new_sev = mapped
                reasons.append(
                    f"Escalated from {original_sev} → {new_sev} due to open risky port(s): {', '.join(map(str, risky_open_fw))}"
                )

    # --- Active scan-based escalation ---
    active_scan_cfg = config.get("active_scan", {})
    if active_scan_cfg.get("enabled", False):
        target_ip = str(row.get("ip", "")).strip()
        if target_ip:
            nonstd_ports = config.get("non_standard_ports", [])
            if nonstd_ports:
                timeout = float(active_scan_cfg.get("timeout_seconds", 0.5))
                workers = int(active_scan_cfg.get("max_workers", 20))
                try:
                    open_nonstd = tcp_scan_ports(target_ip, nonstd_ports, timeout, workers)
                except Exception as e:
                    logging.warning("Active scan failed for %s: %s", target_ip, e)
                    open_nonstd = []

                if open_nonstd:
                    order = ["Low", "Medium", "High", "Critical"]
                    try:
                        cur_idx = next((i for i, v in enumerate(order) if v.lower() == original_sev.lower()), None)
                        if cur_idx is not None:
                            new_idx = min(cur_idx + 1, len(order) - 1)
                            new_sev = order[new_idx]
                            reasons.append(
                                f"Escalated from {original_sev} → {new_sev} due to open non-standard port(s): {', '.join(map(str, open_nonstd))}"
                            )
                    except Exception:
                        pass

    escalation_reason = "; ".join(reasons) if reasons else ""
    return new_sev, escalation_reason


# ----------------------------------------------------
# Core data correlation
# ----------------------------------------------------
def correlate_data():
    """
    Correlates vulnerabilities, assets, subnets, and firewall rules.
    Produces a unified DataFrame with consistent 'ip', 'asset_id', and escalation data.
    """
    data_dir = "data"
    try:
        vuln_path = os.path.join(data_dir, "vulnerabilities.csv")
        asset_path = os.path.join(data_dir, "assets.csv")
        subnet_path = os.path.join(data_dir, "subnets.csv")
        fw_path = os.path.join(data_dir, "firewall_rules.csv")

        vuln_df = pd.read_csv(vuln_path) if os.path.exists(vuln_path) else pd.DataFrame()
        asset_df = pd.read_csv(asset_path) if os.path.exists(asset_path) else pd.DataFrame()
        subnet_df = pd.read_csv(subnet_path) if os.path.exists(subnet_path) else pd.DataFrame()
        fw_df = pd.read_csv(fw_path) if os.path.exists(fw_path) else pd.DataFrame()

        if vuln_df.empty:
            return pd.DataFrame()

        # Normalize all column names to lowercase
        for df_ in [vuln_df, asset_df, subnet_df, fw_df]:
            df_.columns = df_.columns.str.strip().str.lower()

        # --- Normalize possible IP column names ---
        for df_temp in [vuln_df, asset_df, subnet_df, fw_df]:
            if "ip_address" in df_temp.columns and "ip" not in df_temp.columns:
                df_temp.rename(columns={"ip_address": "ip"}, inplace=True)
            if "address" in df_temp.columns and "ip" not in df_temp.columns:
                df_temp.rename(columns={"address": "ip"}, inplace=True)
            if "asset.ip" in df_temp.columns and "ip" not in df_temp.columns:
                df_temp.rename(columns={"asset.ip": "ip"}, inplace=True)

        # --- Expand multiple CVEs into separate rows ---
        if "definition.cve" in vuln_df.columns:
            vuln_df["definition.cve"] = vuln_df["definition.cve"].astype(str)
            vuln_df = vuln_df.assign(**{"definition.cve": vuln_df["definition.cve"].str.split(",")}).explode("definition.cve")

        # --- Merge vulnerabilities with assets ---
        if not asset_df.empty and "asset.name" in vuln_df.columns and "asset.name" in asset_df.columns:
            merged = pd.merge(vuln_df, asset_df, on="asset.name", how="left", suffixes=("", "_asset"))
        else:
            merged = vuln_df.copy()

        # --- Ensure unified IP field exists ---
        if "ip" not in merged.columns:
            ip_candidates = [c for c in merged.columns if "ip" in c]
            if ip_candidates:
                merged["ip"] = merged[ip_candidates[0]]
            else:
                merged["ip"] = ""

        # --- Rename key columns for consistency ---
        rename_map = {
            "asset.name": "asset_id",
            "definition.cve": "cve_id",
            "definition.cvss3.base_score": "cvss_score",
        }
        merged.rename(columns=rename_map, inplace=True)

        # --- Derive severity from CVSS if missing ---
        if "severity" not in merged.columns and "cvss_score" in merged.columns:
            def _cvss_to_sev(score):
                try:
                    s = float(score)
                except Exception:
                    return "Unknown"
                if s >= 9: return "Critical"
                if s >= 7: return "High"
                if s >= 4: return "Medium"
                if s > 0: return "Low"
                return "Informational"
            merged["severity"] = merged["cvss_score"].apply(_cvss_to_sev)

        # --- Apply escalation rules ---
        config = load_escalation_config()
        if not merged.empty:
            results = merged.apply(lambda r: _adjust_one(r, fw_df, config), axis=1, result_type="expand")
            merged["severity"], merged["escalation_reason"] = results[0], results[1]

        return merged

    except Exception as e:
        logging.exception("Error correlating data: %s", e)
        return pd.DataFrame()