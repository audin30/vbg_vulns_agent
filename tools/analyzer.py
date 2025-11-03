import pandas as pd

def summarize_vulnerabilities(df: pd.DataFrame) -> str:
    if df.empty:
        return "No vulnerability data available."
    try:
        summary = df.groupby(["severity", "ip_type"]).size().reset_index(name="count")
        return summary.to_string(index=False)
    except Exception as e:
        return f"Error summarizing vulnerabilities: {e}"

def find_critical_assets(df: pd.DataFrame) -> str:
    if df.empty:
        return "No data available."
    try:
        critical_assets = df[df["criticality"].str.lower() == "critical"]
        if critical_assets.empty:
            return "No critical assets found."
        grouped = (
            critical_assets.groupby(["asset_id", "ip", "owner", "severity"])["cve_id"]
            .apply(lambda x: ", ".join(sorted(set(x))))
            .reset_index()
        )
        output = ["Critical Assets with Associated CVEs:\n"]
        for _, row in grouped.iterrows():
            output.append(
                f"- {row['asset_id']} ({row['ip']}, Owner: {row['owner']})\n"
                f"  Severity: {row['severity']}\n"
                f"  CVEs: {row['cve_id']}\n"
            )
        return "\n".join(output)
    except Exception as e:
        return f"Error listing critical assets: {e}"

def summarize_assets(df: pd.DataFrame) -> str:
    if df.empty:
        return "No asset data available."
    try:
        asset_summary = (
            df.groupby(["criticality", "ip_type"]).size().reset_index(name="count")
        )
        return asset_summary.to_string(index=False)
    except Exception as e:
        return f"Error summarizing assets: {e}"