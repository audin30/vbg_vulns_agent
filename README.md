# 🧠 vbg_vulns_agent
*AI-Powered Vulnerability Management Assistant*

[![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/)
[![LangChain](https://img.shields.io/badge/LangChain-Framework-efefef.svg?logo=chainlink&logoColor=blue)](https://www.langchain.com/)
[![OpenAI](https://img.shields.io/badge/OpenAI-gpt--4o--mini-412991.svg?logo=openai&logoColor=white)](https://openai.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> Developed in **collaboration with ChatGPT and OpenAI**,  
> designed and built by **Juan Janolo ([@audin30](https://github.com/audin30))**.

---

## 🧩 Overview

**vbg_vulns_agent** is an intelligent **LLM-driven Vulnerability Management Assistant** that helps security teams analyze, correlate, and prioritize vulnerabilities using natural language.

By combining vulnerability data (e.g., Tenable, OpenVAS), asset inventories (e.g., phpIPAM), and subnet information, it provides clear, AI-assisted insights into your organization’s risk posture.

---

## 🚀 Key Features

- 🔍 **Data Correlation** — Merges vulnerability, asset, and subnet information into one unified view.  
- 🤖 **AI Query Interface** — Ask natural-language questions about your vulnerabilities.  
- 🔄 **Auto-Reloading Data** — Automatically detects and reloads CSV updates in real time.  
- 🧠 **LLM Reasoning** — Uses OpenAI’s cost-effective `gpt-4o-mini` model.  
- 🧩 **Multi-CVE Support** — Each asset can list multiple CVEs and have them grouped automatically.  
- 📊 **Supports Raw Data Headers** — Reads real-world dataset headers like `asset.name`, `definition.cve`, and `definition.cvss3.base_score`.  
- 🪵 **Logging & Error Handling** — Tracks reloads, data integrity, and operational messages.  
- 🧱 **Modular Design** — Easily extendable for new data sources or AI-driven enrichment.

---

## 🏗️ Project Structure

```
vbg_vuln_agent/
├── app.py                  # Main CLI interface and AI agent
├── tools/
│   ├── data_tools.py       # Handles data loading, merging, and subnet correlation (multi-CVE aware)
│   └── analyzer.py         # Provides summarization and prioritization logic
├── data/
│   ├── vulnerabilities.csv # Sample vulnerability data (supports raw headers and multiple CVEs)
│   ├── assets.csv          # Sample asset data
│   └── subnets.csv         # Sample subnet definitions
├── requirements.txt        # Dependencies
└── README.md               # Project documentation
```

---

## 🧰 Tech Stack

| Component | Technology |
|------------|-------------|
| **Language** | Python 3.12+ |
| **Framework** | LangChain (ReAct agent) |
| **LLM Provider** | OpenAI GPT (`gpt-4o-mini`) |
| **Data Format** | CSV (Vulnerability, Asset, Subnet) |
| **Environment** | Virtualenv or venv |

---

## ⚙️ Installation

### 1️⃣ Clone the repository
```bash
git clone https://github.com/audin30/vbg_vulns_agent.git
cd vbg_vulns_agent
```

### 2️⃣ Create and activate a virtual environment
```bash
python3.12 -m venv venv
source venv/bin/activate
```

### 3️⃣ Install dependencies
```bash
pip install -r requirements.txt
```

### 4️⃣ Set your OpenAI API key
Create a `.env` file in the project root:
```
OPENAI_API_KEY=sk-your-openai-key-here
```

---

## ▶️ Running the Agent

```bash
python app.py
```

Then ask natural language queries like:
```
Summarize my asset distribution.
List all critical assets and their CVEs.
Summarize vulnerabilities by severity and subnet.
```

Example Output:
```
🔄 Detected change in data files — reloading...
✅ Data reloaded successfully.
🤖 Severity  ip_type   count
High        Internal   2
Critical    External   1
```

---

## 🧠 Example Data

### `data/vulnerabilities.csv`
*(Now aligned with real-world exported field names)*
```csv
asset.name,definition.cve,definition.cvss3.base_score,severity
web01,CVE-2024-1111;CVE-2024-2222,8.9,High
db01,CVE-2023-5421;CVE-2023-7890,9.8,Critical
```

### `data/assets.csv`
```csv
asset_id,ip,owner,criticality
web01,10.0.0.10,IT Operations,High
db01,10.0.1.5,Finance,Critical
```

### `data/subnets.csv`
```csv
subnet,type,description
10.0.0.0/24,Internal,Corporate Web Servers
172.16.0.0/16,External,Public Systems
```

> The program automatically maps raw headers to normalized fields (`asset.name` → `asset_id`, `definition.cve` → `cve_id`, etc.) for internal use.

---

## 💡 Roadmap

- [ ] Streamlit web dashboard with chat interface  
- [ ] Integration with Tenable / phpIPAM APIs  
- [ ] EPSS scoring and exploit intelligence enrichment  
- [ ] RAG (Retrieval-Augmented Generation) for contextual CVE lookups  
- [ ] Slack / Teams remediation reporting  

---

## 🪵 Logs

The application logs to both the console and `agent.log`, recording:
- Reload events  
- Errors and exceptions  
- Data validation and operational messages

---

## 🤝 Credits & Collaboration

This project was designed by audin30. Coding done by OpenAI/ChatGPT

> Together, the goal is to make vulnerability management more intelligent, contextual, and efficient.

---

## ⚖️ License

Released under the **MIT License**.  
See the [LICENSE](LICENSE) file for details.
