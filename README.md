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

- 🔍 **Data Correlation** — Merges vulnerability, asset, and subnet information into one view.  
- 🤖 **AI Query Interface** — Ask natural-language questions about your vulnerabilities.  
- 🔄 **Auto-Reloading Data** — Automatically detects and reloads CSV updates in real time.  
- 🧠 **LLM Reasoning** — Uses OpenAI’s `gpt-4o-mini` model for accurate and efficient responses.  
- 🪵 **Logging & Error Handling** — Tracks reloads, errors, and data integrity in real-time logs.  
- 🧱 **Modular Design** — Extendable for new data sources or AI-driven enrichment.

---

## 🏗️ Project Structure

```
vbg_vuln_agent/
├── app.py                  # Main CLI interface and AI agent
├── tools/
│   ├── data_tools.py       # Handles data loading, merging, and subnet correlation
│   └── analyzer.py         # Provides summarization and prioritization logic
├── data/
│   ├── vulnerabilities.csv # Sample vulnerability data
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
Show all critical assets and their vulnerabilities.
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
```csv
cve_id,asset_id,severity,cvss_score,description
CVE-2024-1234,web01,High,8.9,Remote code execution in Apache
CVE-2023-5421,db01,Critical,9.8,Privilege escalation in kernel
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

This project was **designed and developed by [Juan Janolo (audin30)](https://github.com/audin30)**  
in close **collaboration with ChatGPT and OpenAI**, combining security domain expertise with state-of-the-art AI technology.

> Together, the goal is to make vulnerability management more intelligent, contextual, and efficient.

---

## ⚖️ License

Released under the **MIT License**.  
See the [LICENSE](LICENSE) file for details.
