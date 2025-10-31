#!/usr/bin/env python3

def summarize_vulnerabilities(df):
	summary = df.groupby(["severity", "ip_type"]).size().reset_index(name="count")
	return summary.to_string(index=False)

def find_critical_assets(df):
	critical = df[df["criticality"] == "Critical"]
	return critical[["asset_id", "ip", "severity", "cve_id"]].to_string(index=False)