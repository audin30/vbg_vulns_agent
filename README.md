# 🛡️ VBG Vulnerability Intelligence Agent

An AI-powered **Vulnerability Management Agent** that analyzes, summarizes, and prioritizes security findings from multiple sources (Wiz, Tenable, IPAM, Firewall rules, etc.) — dynamically adjusting risk based on **network exposure** and **contextual intelligence**.

Developed in collaboration with **ChatGPT + OpenAI**,  
designed and built by **Juan Janolo**.

---

## 🚀 Features

| Category | Description |
|-----------|--------------|
| 🧠 **LLM-Powered Analysis** | Uses an OpenAI GPT model (default: `gpt-4o-mini`) for intelligent reasoning and summaries. |
| 🔍 **CSV Ingestion** | Reads data from Wiz, Tenable, and IPAM CSV exports. |
| 🧩 **Modular Tools** | Built with separate `tools/` modules for data correlation and analysis. |
| 🔥 **Dynamic Severity Adjustment** | Automatically increases severity based on exposed ports in firewall rules. |
| ⚙️ **Configurable Rules** | Easily modify escalation logic in `config/severity_rules.json`. |
| 🧾 **Escalation Reason Tracking** | Each vulnerability escalation includes a clear reason (e.g., “Escalated from High to Critical due to open port(s): 22”). |
| 💬 **Natural Language CLI** | Query vulnerabilities conversationally (“List High and Critical vulnerabilities”). |
| 💾 **Optional CSV Export** | Only exports data when explicitly requested (e.g., “Export High and Critical vulnerabilities to CSV”). |
| 🔄 **Auto Data Reload** | Automatically reloads if CSV files are updated. |
| 🪵 **Logging** | Logs actions, errors, and data changes to `agent.log`. |

---

## 🧱 Project Structure

```
vbg_vuln_agent/
├── app.py
├── tools/
│   ├── data_tools.py
│   └── analyzer.py
├── data/
│   ├── vulnerabilities.csv
│   ├── assets.csv
│   ├── subnets.csv
│   └── firewall_rules.csv
├── config/
│   └── severity_rules.json
├── output/
└── README.md
```

---

## ⚙️ Configurable Escalation Rules

Modify escalation behavior easily in `config/severity_rules.json`:

```json
{
  "risky_ports": [22, 3389, 3306],
  "escalation_map": {
    "Low": "Medium",
    "Medium": "High",
    "High": "Critical",
    "Critical": "Critical"
  },
  "notes": "You can modify risky ports and escalation levels here."
}
```

💡 Example:  
If port `22` (SSH) or `3389` (RDP) is open and the vulnerability is “High”,  
it is automatically escalated to “Critical”.

---

## 💬 Example CLI Usage

Run the agent:
```bash
python3 app.py
```

### Example Queries

| Query | Behavior |
|--------|-----------|
| `List critical vulnerabilities` | Shows Critical vulnerabilities only. |
| `Show high and medium vulnerabilities` | Filters multiple severities. |
| `Export high and critical vulnerabilities to CSV` | Exports filtered vulnerabilities to `/output/`. |
| `List all high vulnerabilities` | Shows high-severity vulnerabilities with escalation reasons. |

---

## 🧾 Escalation Reason Example

| asset_id | cve_id | severity | escalation_reason |
|-----------|---------|----------|-------------------|
| web01 | CVE-2024-1111 | Critical | Escalated from High to Critical due to open port(s): 22 |
| db01 | CVE-2023-7890 | Critical | Escalated from High to Critical due to open port(s): 3389 |

---

## 🧠 Example CLI Output

```
Vulnerabilities with severities (High, Critical):

╒═══════════╤══════════════╤════════════╤═════════════╤════════════╤══════════════════╤══════════════════════════════════════════════════════════════╕
│ Asset_id  │ Cve_id       │ Severity   │ Cvss_score  │ Ip         │ Owner            │ Escalation_reason                                               │
╞═══════════╪══════════════╪════════════╪═════════════╪════════════╪══════════════════╪══════════════════════════════════════════════════════════════╡
│ web01     │ CVE-2024-1111│ [91mCritical[0m │ 8.9         │ 10.0.0.10  │ IT Operations    │ Escalated from High to Critical due to open port(s): 22        │
│ db01      │ CVE-2023-7890│ [91mCritical[0m │ 9.8         │ 10.0.1.5   │ Finance          │ Escalated from High to Critical due to open port(s): 3389      │
╘═══════════╧══════════════╧════════════╧═════════════╧════════════╧══════════════════╧══════════════════════════════════════════════════════════════╛

⚠️ 2 vulnerabilities escalated due to risky open ports.
```

---

## 💾 Optional CSV Export

Export only when explicitly requested:

```bash
> Export high and critical vulnerabilities to CSV
```

💾 Output saved to:
```
output/vulns_High_Critical_4rows_2025-10-31_185204.csv
```

✅ Includes all escalation details, making reports fully traceable.

---

## 🧰 Requirements

Install dependencies:
```bash
pip install -r requirements.txt
```

### Example requirements.txt
```
pandas
tabulate
langchain
langchain-openai
python-dotenv
openai
```

---

## 🧩 Credits

Developed by **Juan Janolo**  
🤖 In collaboration with **ChatGPT and OpenAI**
