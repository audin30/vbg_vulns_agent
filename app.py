import os
import sys
import logging
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain.agents import create_react_agent, AgentExecutor
from langchain.tools import Tool
from langchain import hub

# --- Setup logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("agent.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

# --- Load environment variables ---
if not load_dotenv():
    logging.warning("⚠️ .env file not found or unreadable. Make sure OPENAI_API_KEY is set.")

if not os.getenv("OPENAI_API_KEY"):
    logging.error("❌ Missing OPENAI_API_KEY in environment.")
    sys.exit(1)

# --- Import local tools ---
try:
    from tools.data_tools import correlate_data
    from tools.analyzer import summarize_vulnerabilities, find_critical_assets, summarize_assets
except ImportError as e:
    logging.error(f"❌ Failed to import tools: {e}")
    sys.exit(1)

# --- Helper: track file modification times ---
def get_file_timestamps():
    """Return a dict of {filename: last_modified_timestamp} for all CSVs in ./data."""
    timestamps = {}
    data_path = "data"
    if not os.path.exists(data_path):
        logging.error("❌ Missing ./data directory.")
        return timestamps
    for file in os.listdir(data_path):
        if file.endswith(".csv"):
            full_path = os.path.join(data_path, file)
            timestamps[file] = os.path.getmtime(full_path)
    return timestamps

# --- Load data initially ---
try:
    df = correlate_data()
    if df.empty:
        logging.warning("⚠️ Data correlation returned an empty dataframe. Check your CSV files.")
except FileNotFoundError as e:
    logging.error(f"❌ Missing data file: {e.filename}")
    sys.exit(1)
except Exception as e:
    logging.exception(f"❌ Unexpected error while loading data: {e}")
    sys.exit(1)

last_timestamps = get_file_timestamps()

# --- Function to check for data updates ---
def refresh_data_if_changed():
    """Reloads CSVs if any data file has changed."""
    global df, last_timestamps
    try:
        current_timestamps = get_file_timestamps()
        if not current_timestamps:
            return
        if current_timestamps != last_timestamps:
            logging.info("🔄 Detected change in data files — reloading...")
            df = correlate_data()
            last_timestamps = current_timestamps
            logging.info("✅ Data reloaded successfully.")
    except Exception as e:
        logging.exception(f"Error during auto-reload: {e}")

# --- Define tool functions ---
def get_vulnerability_summary(_):
    try:
        refresh_data_if_changed()
        return summarize_vulnerabilities(df)
    except Exception as e:
        logging.exception(f"Error summarizing vulnerabilities: {e}")
        return "Error summarizing vulnerabilities."

def get_critical_assets(_):
    try:
        refresh_data_if_changed()
        return find_critical_assets(df)
    except Exception as e:
        logging.exception(f"Error finding critical assets: {e}")
        return "Error finding critical assets."

def get_asset_summary(_):
    try:
        refresh_data_if_changed()
        return summarize_assets(df)
    except Exception as e:
        logging.exception(f"Error summarizing assets: {e}")
        return "Error summarizing assets."

# --- Register tools ---
tools = [
    Tool(
        name="Summarize Vulnerabilities",
        func=get_vulnerability_summary,
        description="Summarizes vulnerabilities by severity and subnet type."
    ),
    Tool(
        name="List Critical Assets",
        func=get_critical_assets,
        description="Lists assets marked as critical with their CVEs and severity."
    ),
    Tool(
        name="Summarize Assets",
        func=get_asset_summary,
        description="Summarizes asset distribution by criticality and IP type."
    ),
]

# --- Initialize LLM and agent ---
try:
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    # Remove unsupported parameter in case of older SDKs
    llm._default_params.pop("stop", None)
    prompt = hub.pull("hwchase17/react")
    agent = create_react_agent(llm=llm, tools=tools, prompt=prompt)
    agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True)
except Exception as e:
    logging.exception(f"❌ Failed to initialize agent: {e}")
    sys.exit(1)

# --- Main interactive loop ---
logging.info("✅ Vulnerability Agent ready! Type 'exit' or 'quit' to stop.")

while True:
    try:
        query = input("\n🔍 Ask your vulnerability agent: ").strip()
        if query.lower() in ["exit", "quit"]:
            logging.info("👋 Exiting agent. Goodbye!")
            break
        if not query:
            continue

        refresh_data_if_changed()
        response = agent_executor.invoke({"input": query})
        print("\n🤖", response["output"])
    except KeyboardInterrupt:
        print("\n👋 Interrupted. Exiting...")
        break
    except Exception as e:
        logging.exception(f"Unexpected error during query: {e}")
        print("⚠️ Something went wrong. Check agent.log for details.")