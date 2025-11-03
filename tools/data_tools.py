import os
import json
import pandas as pd
from ipaddress import ip_network, ip_address

CONFIG_PATH = "config/severity_rules.json"

def load_escalation_config():
    """
    Loads severity escalation configuration from JSON.
    Falls back to defaults if missing.
    """
    default_config = {
        "risky_ports": [22, 3389, 3306],
        "escalation_map": {
            "Low": "Medium",
            "Medium": "High",
            "High": "Critical",
            "Critical": "Critical"
        }
    }

    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as f:
                cfg = json.load(f)
            return cfg
        except Exception as e:
            print(f"⚠️ Warning: Failed to read config file: {e}")
            return default_config
    else:
        print("⚠️ Config file not found. Using default escalation rules.")
        return default_config


def load_data():
    """
    Load vulnerabilities, assets, subnets, and firewall rules.
    """
    vulns = pd.read_csv("data/vulnerabilities.csv")
    assets = pd.read_csv("data/assets.csv")
    subnets = pd.read_csv("data/subnets.csv")
    firewall = pd.read_csv("data/firewall_rules.csv")

    vulns = vulns.rename(columns={
        "asset.name": "asset_id",
        "definition.cve": "cve_id",
        "definition.cvss3.base_score": "cvss_score"
    })

    # Expand CVEs into separate rows
    expanded_rows = []
    for _, row in vulns.iterrows():
        cves = str(row.get("cve_id", "")).replace(",", ";").split(";")
        for cve in [c.strip() for c in cves if c.strip()]:
            new_row = row.copy()
            new_row["cve_id"] = cve
            expanded_rows.append(new_row)
    vulns = pd.DataFrame(expanded_rows)
    return vulns, assets, subnets, firewall


def find_subnet(ip, subnets):
    for _, row in subnets.iterrows():
        try:
            if ip_address(ip) in ip_network(row["subnet"]):
                return row["type"]
        except ValueError:
            continue
    return "Unknown"


def adjust_severity(row, firewall_df, config):
    """
    Increase severity if the asset has risky ports allowed.
    Adds escalation_reason column to explain why severity was increased.
    """
    risky_ports = config.get("risky_ports", [])
    escalation = config.get("escalation_map", {})

    # Match firewall rules for the current asset
    asset_rules = firewall_df[
        (firewall_df["asset_id"] == row["asset_id"]) &
        (firewall_df["action"].str.lower() == "allow")
    ]

    # Check if any risky ports are open
    risky_open = [p for p in asset_rules["port"].astype(int) if p in risky_ports]

    if not risky_open:
        return row["severity"], ""

    # Escalate severity
    new_sev = escalation.get(row["severity"], row["severity"])
    reason = f"Escalated from {row['severity']} to {new_sev} due to open port(s): {', '.join(map(str, risky_open))}"
    return new_sev, reason


def correlate_data():
    """
    Merge all datasets and apply escalation logic.
    Adds 'escalation_reason' column for traceability.
    """
    vulns, assets, subnets, firewall = load_data()
    config = load_escalation_config()

    merged = pd.merge(vulns, assets, left_on="asset_id", right_on="asset_id", how="left")
    merged["ip_type"] = merged["ip"].apply(lambda x: find_subnet(x, subnets))

    # Apply escalation
    results = merged.apply(lambda r: adjust_severity(r, firewall, config), axis=1)
    merged["severity"], merged["escalation_reason"] = zip(*results)

    return merged