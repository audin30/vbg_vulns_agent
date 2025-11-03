import pandas as pd
from ipaddress import ip_network, ip_address

def load_data():
    vulns = pd.read_csv("data/vulnerabilities.csv")
    assets = pd.read_csv("data/assets.csv")
    subnets = pd.read_csv("data/subnets.csv")
    firewall = pd.read_csv("data/firewall_rules.csv")

    vulns = vulns.rename(columns={
        "asset.name": "asset_id",
        "definition.cve": "cve_id",
        "definition.cvss3.base_score": "cvss_score"
    })

    # Expand CVEs
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


def adjust_severity(row, firewall_df):
    """
    Increase severity if the asset has risky ports allowed.
    Example: SSH (22), RDP (3389), MySQL (3306) → escalate by 1 level.
    """
    risky_ports = [22, 3389, 3306]
    asset_rules = firewall_df[(firewall_df["asset_id"] == row["asset_id"]) & 
                              (firewall_df["action"].str.lower() == "allow")]

    # Find intersection of risky ports
    risky_open = any(p in list(asset_rules["port"]) for p in risky_ports)
    if not risky_open:
        return row["severity"]

    # Define escalation map
    escalation = {
        "Low": "Medium",
        "Medium": "High",
        "High": "Critical",
        "Critical": "Critical"
    }
    return escalation.get(row["severity"], row["severity"])


def correlate_data():
    vulns, assets, subnets, firewall = load_data()
    merged = pd.merge(vulns, assets, left_on="asset_id", right_on="asset_id", how="left")
    merged["ip_type"] = merged["ip"].apply(lambda x: find_subnet(x, subnets))

    # 🔥 Adjust severity dynamically based on firewall exposure
    merged["severity"] = merged.apply(lambda r: adjust_severity(r, firewall), axis=1)
    return merged