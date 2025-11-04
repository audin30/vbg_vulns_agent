import pandas as pd

def get_vulnerability_summary(df: pd.DataFrame) -> str:
    if df.empty:
        return "No vulnerability data available."
    try:
        summary = df.groupby(["severity","ip_type"]).size().reset_index(name="count")
        return summary.to_string(index=False)
    except Exception as e:
        return f"Error summarizing vulnerabilities: {e}"

def get_critical_assets(df: pd.DataFrame) -> str:
    if df.empty:
        return "No data available."
    try:
        mask = df["criticality"].astype(str).str.lower() == "critical"
        critical_assets = df[mask]
        if critical_assets.empty:
            return "No critical assets found."
        grouped = (
            critical_assets.groupby(["asset_id","ip","owner","severity"])["cve_id"]
            .apply(lambda x: ", ".join(sorted(set(map(str, x)))))
            .reset_index(name="cve_list")
        )
        lines = ["Critical Assets with Associated CVEs:\n"]
        for _, r in grouped.iterrows():
            lines.append(
                f"- {r['asset_id']} ({r['ip']}, Owner: {r['owner']})\n"
                f"  Severity: {r['severity']}\n"
                f"  CVEs: {r['cve_list']}\n"
            )
        return "\n".join(lines)
    except Exception as e:
        return f"Error listing critical assets: {e}"

def get_asset_summary(df: pd.DataFrame) -> str:
    if df.empty:
        return "No asset data available."
    try:
        summary = df.groupby(["criticality","ip_type"]).size().reset_index(name="count")
        return summary.to_string(index=False)
    except Exception as e:
        return f"Error summarizing assets: {e}"
