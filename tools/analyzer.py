import pandas as pd

def summarize_vulnerabilities(df: pd.DataFrame) -> str:
    """
    Summarize vulnerabilities by severity and network type.
    Returns a formatted table as string.
    """
    if df.empty:
        return "No vulnerability data available."

    try:
        summary = (
            df.groupby(["severity", "ip_type"])
            .size()
            .reset_index(name="count")
            .sort_values(by=["severity", "ip_type"], ascending=True)
        )
        return summary.to_string(index=False)
    except Exception as e:
        return f"Error summarizing vulnerabilities: {e}"


def find_critical_assets(df: pd.DataFrame) -> str:
    """
    Lists critical assets with associated CVEs (grouped by asset).
    """
    if df.empty:
        return "No data available."

    try:
        # Filter only critical assets
        critical_assets = df[df["criticality"].str.lower() == "critical"]

        if critical_assets.empty:
            return "No critical assets found."

        # Group by asset and aggregate CVEs
        grouped = (
            critical_assets.groupby(["asset_id", "ip", "owner", "severity"])["cve_id"]
            .apply(lambda x: ", ".join(sorted(set(x))))
            .reset_index()
            .rename(columns={"cve_id": "cve_list"})
        )

        output = ["Critical Assets with Associated CVEs:\n"]
        for _, row in grouped.iterrows():
            output.append(
                f"- {row['asset_id']} ({row['ip']}, Owner: {row['owner']})\n"
                f"  Severity: {row['severity']}\n"
                f"  CVEs: {row['cve_list']}\n"
            )

        return "\n".join(output)
    except Exception as e:
        return f"Error listing critical assets: {e}"


def summarize_assets(df: pd.DataFrame) -> str:
    """
    Provides a quick overview of asset distribution by criticality and IP type.
    """
    if df.empty:
        return "No asset data available."

    try:
        asset_summary = (
            df.groupby(["criticality", "ip_type"])
            .size()
            .reset_index(name="count")
            .sort_values(by=["criticality", "ip_type"])
        )
        return asset_summary.to_string(index=False)
    except Exception as e:
        return f"Error summarizing assets: {e}"