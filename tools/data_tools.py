import os
import json
import socket
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

# -------------------------------
# Config loader
# -------------------------------
def load_escalation_config(path="config/severity_rules.json"):
    """Load escalation rules and port config."""
    try:
        if not os.path.exists(path):
            logging.warning("Config file missing: %s", path)
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


# -------------------------------
# Lightweight TCP connect scan
# -------------------------------
def tcp_scan_ports(ip: str, ports: list, timeout: float = 0.5, max_workers: int = 20) -> list:
    """
    Lightweight TCP connect scan (parallel).
    Returns a sorted list of open ports (ints).
    """
    open_ports = []

    def _probe(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((ip, int(port)))
                return port if result == 0 else None
        except Exception:
            return None

    ports = [int(p) for p in ports] if ports else []
    if not ports:
        return []

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_probe, p): p for p in ports}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                open_ports.append(int(res))

    return sorted(set(open_ports))


# -------------------------------
# Severity adjustment
# -------------------------------
def _adjust_one(row, firewall_df, config):
    """
    Adjust severity for a single row based on:
      - firewall allow rules (risky ports)
      - optional active scanning (non-standard ports)
    Returns: (new_severity, escalation_reason)
    """
    risky_ports = config.get("risky_ports", [])
    esc_map = config.get("escalation_map", {})

    # Handle firewall rules
    if firewall_df.empty or not all(c in firewall_df.columns for c in ("asset_id", "port", "action")):
        firewall_matches = []
    else:
        firewall_matches = firewall_df[
            (firewall_df["asset_id"].astype(str) == str(row.get("asset_id", ""))) &
            (firewall_df["action"].astype(str).str.lower() == "allow")
        ]

    try:
        open_ports_fw = [int(p) for p in firewall_matches["port"].tolist()] if not isinstance(firewall_matches, list) else []
    except Exception:
        open_ports_fw = []

    risky_open_fw = [p for p in open_ports_fw if p in risky_ports]

    original_sev = str(row.get("severity", "")).strip() or ""
    new_sev = original_sev
    reasons = []

    # Firewall-based escalation
    if risky_open_fw:
        mapped = esc_map.get(original_sev, original_sev)
        if mapped != original_sev:
            new_sev = mapped
            reasons.append(f"Escalated from {original_sev} to {new_sev} due to open port(s): {', '.join(map(str, risky_open_fw))}")

    # -----------------------
    # Optional Active Scan
    # -----------------------
    active_scan_cfg = config.get("active_scan", {})
    if active_scan_cfg.get("enabled", False):
        target_ip = str(row.get("ip", "")).strip()
        if target_ip:
            nonstd = config.get("non_standard_ports", [])
            if nonstd:
                timeout = float(active_scan_cfg.get("timeout_seconds", 0.5))
                max_workers = int(active_scan_cfg.get("max_workers", 20))
                try:
                    open_nonstd = tcp_scan_ports(target_ip, nonstd, timeout, max_workers)
                except Exception as e:
                    open_nonstd = []
                    logging.warning("Active scan failed for %s: %s", target_ip, e)

                if open_nonstd:
                    # bump severity by one level
                    order = ["Low", "Medium", "High", "Critical"]
                    try:
                        cur_idx = next((i for i, v in enumerate(order) if v.lower() == original_sev.lower()), None)
                        if cur_idx is not None:
                            new_idx = min(cur_idx + 1, len(order) - 1)
                            new_sev = order[new_idx]
                            reasons.append(
                                f"Escalated from {original_sev} to {new_sev} due to open non-standard port(s): {', '.join(map(str, open_nonstd))}"
                            )
                    except Exception:
                        pass

    escalation_reason = "; ".join(reasons) if reasons else ""
    return new_sev, escalation_reason


# -------------------------------
# Data correlation
# -------------------------------
def correlate_data():
    """
    Correlates vulnerabilities.csv, assets.csv, subnets.csv, firewall_rules.csv.
    Applies escalation logic and returns merged DataFrame.
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

        # Normalize column names
        vuln_df.columns = vuln_df.columns.str.strip().str.lower()
        asset_df.columns = asset_df.columns.str.strip().str.lower()
        subnet_df.columns = subnet_df.columns.str.strip().str.lower()
        fw_df.columns = fw_df.columns.str.strip().str.lower()

        # Expand multiple CVEs if present
        if "definition.cve" in vuln_df.columns:
            vuln_df["definition.cve"] = vuln_df["definition.cve"].astype(str)
            vuln_df = vuln_df.assign(**{"definition.cve": vuln_df["definition.cve"].str.split(",")}).explode("definition.cve")

        # Merge vulnerabilities with assets by asset.name
        # --- Normalize IP field naming in all datasets ---
        for df_temp in [vuln_df, asset_df, subnet_df, fw_df]:
            if "ip_address" in df_temp.columns and "ip" not in df_temp.columns:
                df_temp.rename(columns={"ip_address": "ip"}, inplace=True)
            if "address" in df_temp.columns and "ip" not in df_temp.columns:
                df_temp.rename(columns={"address": "ip"}, inplace=True)
            if "asset.ip" in df_temp.columns and "ip" not in df_temp.columns:
                df_temp.rename(columns={"asset.ip": "ip"}, inplace=True)
                
        # --- Merge vulnerabilities with assets by asset.name (if available) ---
        if not asset_df.empty and "asset.name" in vuln_df.columns and "asset.name" in asset_df.columns:
            merged = pd.merge(vuln_df, asset_df, on="asset.name", how="left", suffixes=("", "_asset"))
        else:
            merged = vuln_df.copy()
            
        # --- Ensure unified IP field exists ---
        if "ip" not in merged.columns:
            # Try to extract from merged asset fields
            ip_candidates = [c for c in merged.columns if "ip" in c]
            if ip_candidates:
                merged["ip"] = merged[ip_candidates[0]]
            else:
                merged["ip"] = ""

        # Map renamed fields for consistency
        rename_map = {
            "asset.name": "asset_id",
            "definition.cve": "cve_id",
            "definition.cvss3.base_score": "cvss_score",
        }
        merged.rename(columns=rename_map, inplace=True)

        # Fill missing severity with fallback logic
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

        # Apply escalation
        config = load_escalation_config()
        if not merged.empty:
            results = merged.apply(lambda r: _adjust_one(r, fw_df, config), axis=1, result_type="expand")
            merged["severity"], merged["escalation_reason"] = results[0], results[1]

        return merged

    except Exception as e:
        logging.exception("Error correlating data: %s", e)
        return pd.DataFrame()