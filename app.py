import os
import sys
import time
import logging
from datetime import datetime
from dotenv import load_dotenv
import pandas as pd
from langchain import hub
from langchain.agents import create_react_agent, AgentExecutor, Tool
from langchain_openai import ChatOpenAI
from tools.data_tools import correlate_data
from tools.analyzer import summarize_vulnerabilities, find_critical_assets, summarize_assets
from tabulate import tabulate

# --- Load environment variables ---
load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# --- Logging ---
logging.basicConfig(
    filename="agent.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# --- Initial data load ---
df = correlate_data()
data_files = ["data/vulnerabilities.csv", "data/assets.csv", "data/subnets.csv"]
last_modified = {f: os.path.getmtime(f) for f in data_files if os.path.exists(f)}

num_escalated = len(df[df["escalation_reason"].str.len() > 0])
if num_escalated > 0:
    print(f"\n⚠️ {num_escalated} vulnerabilities had their severity escalated due to open risky ports.\n")

def refresh_data_if_changed():
    global df, last_modified
    changed = False
    for f in data_files:
        if os.path.exists(f):
            new_time = os.path.getmtime(f)
            if new_time > last_modified.get(f, 0):
                changed = True
                last_modified[f] = new_time
    if changed:
        logging.info("Detected change in data files — reloading.")
        df = correlate_data()

# --- LLM setup and connection verification ---
try:
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    llm._default_params.pop("stop", None)

    MODEL_PRICING = {
        "gpt-4o-mini": {"input": 0.15, "output": 0.60},
        "gpt-4o": {"input": 2.50, "output": 10.00},
        "gpt-3.5-turbo": {"input": 0.50, "output": 1.50}
    }

    model_name = getattr(llm, "model_name", "unknown-model")
    pricing = MODEL_PRICING.get(model_name, {"input": 0.0, "output": 0.0})
    print("\n──────────────────────────────────────────────")
    print(f"🤖  Model: \033[96m{model_name}\033[0m")
    print(f"💰  Pricing: \033[93m${pricing['input']}/1M input tokens\033[0m | \033[93m${pricing['output']}/1M output tokens\033[0m")
    print("──────────────────────────────────────────────")

    print("\n🧠 Initializing LLM connection to OpenAI...")
    test_response = llm.invoke("ping")
    print("\033[92m✅ LLM ONLINE\033[0m — Connected successfully!")
except Exception as e:
    print("\033[91m❌ LLM OFFLINE\033[0m — Failed to connect to OpenAI.")
    logging.exception("LLM connection failed.")
    sys.exit(1)

# --- Agent tools ---
def get_vulnerability_summary(_):
    refresh_data_if_changed()
    return summarize_vulnerabilities(df)

def get_critical_assets(_):
    refresh_data_if_changed()
    return find_critical_assets(df)

def get_asset_summary(_):
    refresh_data_if_changed()
    return summarize_assets(df)

def list_vulnerabilities_by_severity(query: str):
    """
    List vulnerabilities by severity, with optional CSV export upon user request.
    Example queries:
        "Show high vulnerabilities"
        "List critical and high vulnerabilities"
        "Export high and critical vulnerabilities to CSV"
    """
    try:
        refresh_data_if_changed()
        
        # --- Detect severity levels ---
        severity_keywords = ["critical", "high", "medium", "low", "info", "informational"]
        requested = [s.capitalize() for s in severity_keywords if s in query.lower()]
        
        if not requested:
            return "Please specify one or more severities (e.g., High, Critical, Medium, Low)."
        
        # --- Detect export intent ---
        export_requested = any(word in query.lower() for word in ["export", "save", "csv", "write"])
        
        # --- Filter data ---
        filtered = df[df["severity"].str.lower().isin([s.lower() for s in requested])]
        if filtered.empty:
            return f"No vulnerabilities found with severities: {', '.join(requested)}."
        
        # --- Display columns ---
        display_cols = [
            col for col in ["asset_id", "cve_id", "severity", "cvss_score", "ip", "owner", "escalation_reason"]
            if col in filtered.columns
        ]
        
        # --- Sort results ---
        sort_cols = ["severity"]
        if "cvss_score" in filtered.columns:
            sort_cols.append("cvss_score")
        filtered = filtered.sort_values(by=sort_cols, ascending=[True, False])
        
        # --- Colorize severity ---
        def colorize(sev):
            s = sev.lower()
            if s == "critical":
                return f"\033[91m{s.capitalize()}\033[0m"  # red
            elif s == "high":
                return f"\033[93m{s.capitalize()}\033[0m"  # yellow
            elif s == "medium":
                return f"\033[33m{s.capitalize()}\033[0m"  # dim yellow
            elif s == "low":
                return f"\033[94m{s.capitalize()}\033[0m"  # blue
            elif s in ["info", "informational"]:
                return f"\033[90m{s.capitalize()}\033[0m"  # gray
            return sev
        
        if "severity" in filtered.columns:
            filtered["severity"] = filtered["severity"].apply(colorize)
            
        # --- Create pretty table ---
        table = tabulate(
            filtered[display_cols],
            headers=[c.capitalize() for c in display_cols],
            tablefmt="fancy_grid",
            showindex=False,
        )
        
        result = f"Vulnerabilities with severities ({', '.join(requested)}):\n\n{table}"
        
        # --- Optional export ---
        if export_requested:
            os.makedirs("output", exist_ok=True)
            row_count = len(filtered)
            timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
            safe_sev = "_".join(requested)
            export_path = f"output/vulns_{safe_sev}_{row_count}rows_{timestamp}.csv"
            
            # Export with escalation_reason included
            filtered.to_csv(export_path, index=False)
            result += f"\n\n💾 Exported \033[92m{row_count}\033[0m rows to: \033[96m{export_path}\033[0m"
            logging.info(f"Exported {row_count} rows to {export_path}")
            
        # --- Add escalation summary ---
        num_escalated = len(filtered[filtered["escalation_reason"].str.len() > 0])
        if num_escalated > 0:
            result += f"\n\n⚠️ {num_escalated} vulnerabilities escalated due to risky open ports."
            
        return result
    
    except Exception as e:
        logging.exception(f"Error filtering vulnerabilities by severity: {e}")
        return f"Error filtering vulnerabilities by severity: {e}"

tools = [
    Tool(name="Summarize Vulnerabilities", func=get_vulnerability_summary, description="Summarizes vulnerabilities by severity and subnet."),
    Tool(name="List Critical Assets", func=get_critical_assets, description="Lists critical assets and their CVEs."),
    Tool(name="Summarize Assets", func=get_asset_summary, description="Summarizes assets by criticality and IP type."),
    Tool(name="List Vulnerabilities by Severity", func=list_vulnerabilities_by_severity, description="Lists vulnerabilities by severity with export.")
]

prompt = hub.pull("hwchase17/react")
agent = create_react_agent(llm=llm, tools=tools, prompt=prompt)
agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True)

# --- CLI Loop ---
print("\n✅ Vulnerability Agent ready! Type 'exit' or 'quit' to stop.\n")
while True:
    user_input = input("🔎 > ").strip()
    if user_input.lower() in ["exit", "quit"]:
        print("👋 Exiting vulnerability agent.")
        break
    try:
        response = agent_executor.invoke({"input": user_input})
        print("\n" + response["output"] + "\n")
    except Exception as e:
        logging.exception(f"Error in main loop: {e}")
        print(f"❌ Error: {e}")