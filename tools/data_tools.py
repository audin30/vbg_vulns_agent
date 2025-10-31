#!/usr/bin/env python3

import pandas as pd
from ipaddress import ip_network, ip_address

def load_data():
	vulns = pd.read_csv("data/vulnerabilities.csv")
	assets = pd.read_csv("data/assets.csv")
	subnets = pd.read_csv("data/subnets.csv")
	return vulns, assets, subnets

def find_subnet(ip, subnets):
	for _, row in subnets.iterrows():
		if ip_address(ip) in ip_network(row['subnet']):
			return row['type']
	return "Unknown"

def correlate_data():
	vulns, assets, subnets = load_data()
	merged = pd.merge(vulns, assets, on="asset_id", how="left")
	merged["ip_type"] = merged["ip"].apply(lambda x: find_subnet(x, subnets))
	return merged