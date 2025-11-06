#!/usr/bin/env python3

import os
import json
import time
import logging
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv

# ------------------------------------------------------------------------
# Setup
# ------------------------------------------------------------------------
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE = "https://www.virustotal.com/api/v3"
CACHE_PATH = ".cache/vt_cache.json"
os.makedirs(".cache", exist_ok=True)

# ------------------------------------------------------------------------
# Utilities
# ------------------------------------------------------------------------
def vt_headers():
	"""Return API headers."""
	if not VT_API_KEY:
		logging.warning("VirusTotal API key not found. Add VT_API_KEY to .env")
	return {"x-apikey": VT_API_KEY or ""}

def _load_cache():
	try:
		if os.path.exists(CACHE_PATH):
			with open(CACHE_PATH, "r") as f:
				return json.load(f)
	except Exception:
		logging.warning("Could not read VT cache.")
	return {}

def _save_cache(cache):
	try:
		with open(CACHE_PATH, "w") as f:
			json.dump(cache, f, indent=2)
	except Exception as e:
		logging.warning("Failed to save VT cache: %s", e)
		
CACHE = _load_cache()

# ------------------------------------------------------------------------
# VirusTotal Queries
# ------------------------------------------------------------------------
def vt_search_cve(cve_id: str, use_cache: bool = True) -> dict:
	"""
	Search VirusTotal for intelligence entries referencing a CVE ID.
	Returns a dict with number of matches and latest analysis time.
	"""
	if not cve_id:
		return {}
	if use_cache and cve_id in CACHE.get("cve", {}):
		return CACHE["cve"][cve_id]
	
	try:
		url = f"{VT_BASE}/intelligence/search?query=cve:{cve_id}"
		r = requests.get(url, headers=vt_headers(), timeout=10)
		if r.status_code == 200:
			data = r.json()
			hits = data.get("data", [])
			result = {
				"cve": cve_id,
				"matches": len(hits),
				"last_analysis": hits[0]["attributes"].get("last_analysis_date") if hits else None,
			}
		elif r.status_code == 429:
			logging.warning("VT rate limit reached. Sleeping before retry...")
			time.sleep(20)
			return vt_search_cve(cve_id, use_cache)
		else:
			logging.warning(f"VT returned {r.status_code} for {cve_id}")
			result = {"cve": cve_id, "matches": 0}
			
		CACHE.setdefault("cve", {})[cve_id] = result
		_save_cache(CACHE)
		return result
	
	except Exception as e:
		logging.exception("VT search failed for %s: %s", cve_id, e)
		return {"cve": cve_id, "matches": 0}
	
	
def vt_enrich_ip(ip: str, use_cache: bool = True) -> dict:
	"""
	Retrieve VT reputation for an IP address.
	Returns last analysis stats (malicious, suspicious, harmless, etc.)
	"""
	if not ip:
		return {}
	if use_cache and ip in CACHE.get("ip", {}):
		return CACHE["ip"][ip]
	
	try:
		url = f"{VT_BASE}/ip_addresses/{ip}"
		r = requests.get(url, headers=vt_headers(), timeout=10)
		if r.status_code == 200:
			data = r.json().get("data", {})
			stats = data.get("attributes", {}).get("last_analysis_stats", {})
			result = {
				"ip": ip,
				"malicious": stats.get("malicious", 0),
				"suspicious": stats.get("suspicious", 0),
				"harmless": stats.get("harmless", 0),
				"last_analysis": data.get("attributes", {}).get("last_analysis_date"),
			}
		elif r.status_code == 429:
			logging.warning("VT rate limit hit on IP lookup. Sleeping...")
			time.sleep(20)
			return vt_enrich_ip(ip, use_cache)
		else:
			result = {"ip": ip, "malicious": 0, "suspicious": 0}
			logging.warning("VT returned %d for IP %s", r.status_code, ip)
			
		CACHE.setdefault("ip", {})[ip] = result
		_save_cache(CACHE)
		return result
	
	except Exception as e:
		logging.warning("VT IP lookup failed for %s: %s", ip, e)
		return {"ip": ip, "malicious": 0, "suspicious": 0}
	
# ------------------------------------------------------------------------
# Bulk / Parallel Enrichment
# ------------------------------------------------------------------------
def vt_bulk_enrich(items, func, label: str, max_workers: int = 5, sleep_per_req: float = 1.0):
	"""
	Run VT queries in parallel with caching + rate limit backoff.
	:param items: list of CVEs or IPs
	:param func: enrichment function (vt_search_cve or vt_enrich_ip)
	"""
	results = []
	if not items:
		return results
	
	with ThreadPoolExecutor(max_workers=max_workers) as ex:
		futures = {ex.submit(func, item): item for item in items}
		for fut in as_completed(futures):
			res = fut.result()
			if res:
				results.append(res)
			time.sleep(sleep_per_req)
	logging.info("Completed VT bulk enrichment for %d %s items", len(results), label)
	return results

# ------------------------------------------------------------------------
# Combined Enrichment Interface
# ------------------------------------------------------------------------
def enrich_dataset(df):
	"""
	Enrich vulnerability dataset with VirusTotal intelligence.
	Adds vt_cve_hits and vt_ip_malicious columns if data present.
	"""
	if df.empty:
		return df
	
	out_df = df.copy()
	
	# --- Enrich CVEs ---
	if "cve_id" in out_df.columns:
		unique_cves = [c for c in out_df["cve_id"].dropna().unique().tolist() if isinstance(c, str)]
		vt_cve_results = vt_bulk_enrich(unique_cves, vt_search_cve, "CVE", max_workers=4)
		vt_cve_map = {r["cve"]: r["matches"] for r in vt_cve_results}
		out_df["vt_cve_hits"] = out_df["cve_id"].map(vt_cve_map).fillna(0).astype(int)
		
	# --- Enrich IPs ---
	if "ip" in out_df.columns:
		unique_ips = [i for i in out_df["ip"].dropna().unique().tolist() if isinstance(i, str) and i.count(".") == 3]
		vt_ip_results = vt_bulk_enrich(unique_ips, vt_enrich_ip, "IP", max_workers=4)
		vt_ip_map = {r["ip"]: r for r in vt_ip_results}
		out_df["vt_ip_malicious"] = out_df["ip"].map(lambda ip: vt_ip_map.get(ip, {}).get("malicious", 0))
		out_df["vt_ip_suspicious"] = out_df["ip"].map(lambda ip: vt_ip_map.get(ip, {}).get("suspicious", 0))
		
	return out_df