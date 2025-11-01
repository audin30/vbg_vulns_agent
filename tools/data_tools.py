import pandas as pd
from ipaddress import ip_network, ip_address

def load_data():
    vulns = pd.read_csv("data/vulnerabilities.csv")
    assets = pd.read_csv("data/assets.csv")
    subnets = pd.read_csv("data/subnets.csv")

    # 🧠 Expand multi-CVE rows into multiple records
    expanded_rows = []
    for _, row in vulns.iterrows():
        cves = str(row["cve_id"]).replace(",", ";").split(";")
        for cve in [c.strip() for c in cves if c.strip()]:
            new_row = row.copy()
            new_row["cve_id"] = cve
            expanded_rows.append(new_row)
    vulns = pd.DataFrame(expanded_rows)

    return vulns, assets, subnets

def find_subnet(ip, subnets):
    for _, row in subnets.iterrows():
        try:
            if ip_address(ip) in ip_network(row["subnet"]):
                return row["type"]
        except ValueError:
            continue
    return "Unknown"

def correlate_data():
    vulns, assets, subnets = load_data()
    merged = pd.merge(vulns, assets, on="asset_id", how="left")
    merged["ip_type"] = merged["ip"].apply(lambda x: find_subnet(x, subnets))
    return merged