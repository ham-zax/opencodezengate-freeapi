# Agent & Harness Integration Guide: ZenGate (`opencodezengate-freeapi`)

> Instructions for autonomous AI coding agents, harnesses, and tools (OpenCode2, Claude Code, Cursor, Agy, Antigravity, Cline, Continue) to launch, configure, and use ZenGate as a high-throughput, free AI model backend.

---

## 1. Automated Setup & Startup (Agent Script)

When an AI agent or automated harness starts up in an environment with ZenGate, it should ensure the gateway daemon is running:

### Step 1: Check if ZenGate is Already Running
```bash
curl -s --connect-timeout 2 http://127.0.0.1:13339/api/status
```

### Step 2: Start ZenGate in Background (If not running)
```bash
# From repository root
nohup bun run gate-docker.ts > /dev/null 2>&1 &

# Wait for gateway health check
until curl -s http://127.0.0.1:13339/api/status | grep -q '"ok":true'; do
  sleep 0.5
done
```

---

## 2. Configuring the Harness: OpenCode & OpenCode2

AI agents managing or interacting with the `opencode` / `opencode2` harness should register ZenGate into `~/.config/opencode/opencode.json`.

### Automated Injection Script (Python)
An agent can run this one-liner to safely inject or update the `zengate` provider in `opencode.json`:

```python
import json, os

config_path = os.path.expanduser("~/.config/opencode/opencode.json")
os.makedirs(os.path.dirname(config_path), exist_ok=True)

try:
    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)
except Exception:
    config = {"$schema": "https://opencode.ai/config.json", "provider": {}}

if "provider" not in config:
    config["provider"] = {}

config["provider"]["zengate"] = {
    "npm": "@ai-sdk/openai-compatible",
    "name": "ZenGate",
    "options": {
        "baseURL": "http://127.0.0.1:13339/v1",
        "apiKey": "admin123"
    },
    "models": {
        "nemotron-3.5-lightning-free": {
            "name": "Nemotron 3.5 Lightning (ZenGate Free)",
            "reasoning": True,
            "limit": {"context": 128000, "output": 8192},
            "modalities": {"input": ["text", "image"], "output": ["text"]}
        },
        "nemotron-3-ultra-free": {
            "name": "Nemotron 3 Ultra (ZenGate Free)",
            "reasoning": True,
            "limit": {"context": 128000, "output": 8192},
            "modalities": {"input": ["text"], "output": ["text"]}
        },
        "hy3-free": {
            "name": "Hunyuan 3 (ZenGate Free)",
            "reasoning": True,
            "limit": {"context": 128000, "output": 8192},
            "modalities": {"input": ["text"], "output": ["text"]}
        },
        "laguna-s-2.1-free": {
            "name": "Laguna S 2.1 (ZenGate Free)",
            "limit": {"context": 128000, "output": 8192},
            "modalities": {"input": ["text"], "output": ["text"]}
        },
        "deepseek-v4-flash-free": {
            "name": "DeepSeek V4 Flash (ZenGate Free)",
            "reasoning": True,
            "limit": {"context": 128000, "output": 8192},
            "modalities": {"input": ["text"], "output": ["text"]}
        },
        "mimo-v2.5-free": {
            "name": "MiMo 2.5 (ZenGate Free)",
            "limit": {"context": 128000, "output": 8192},
            "modalities": {"input": ["text"], "output": ["text"]}
        }
    }
}

with open(config_path, "w", encoding="utf-8") as f:
    json.dump(config, f, indent=4)

print("ZenGate provider successfully configured in opencode.json!")
```

---

## 3. Running Harness Tasks via OpenCode2

Once configured, agents can invoke `opencode2` non-interactively to perform subtasks, code generation, and reviews:

```bash
# Run code generation with Claude Sonnet 4.6
opencode2 run --model zengate/claude-sonnet-4-6 "Implement a TypeScript LRU cache"

# Run fast reasoning with DeepSeek V4 Flash
opencode2 run --model zengate/deepseek-v4-flash-free "Analyze and optimize this SQL query"

# Run high-context tasks with Gemini 3.7 Flash
opencode2 run --model zengate/gemini-3.7-flash "Summarize the changes across all recent git commits"
```

---

## 4. Configuring Other AI Harnesses & Agents

### Claude Code CLI
```bash
export ANTHROPIC_BASE_URL="http://127.0.0.1:13339/v1"
export ANTHROPIC_API_KEY="admin123"
claude "Review the codebase architecture"
```

### Cursor / VS Code (Continue, Cline, Roo Code)
- **API Provider**: OpenAI Compatible
- **Base URL**: `http://127.0.0.1:13339/v1`
- **API Key**: `admin123`
- **Model ID**: `claude-sonnet-4-6` or `deepseek-v4-flash-free`

### Python SDK (`openai`)
```python
from openai import OpenAI

client = OpenAI(
    base_url="http://127.0.0.1:13339/v1",
    api_key="admin123"
)

response = client.chat.completions.create(
    model="claude-sonnet-4-6",
    messages=[{"role": "user", "content": "Write a unit test for user login."}]
)
print(response.choices[0].message.content)
```

---

## 5. Agent Maintenance & Self-Healing Procedures

If an agent experiences upstream rate limits or stale proxy nodes:

1. **Re-benchmark Anycast Edge IPs**:
   ```bash
   python3 scripts/update_cf_ips.py
   ```
   *Scans 1,600+ Cloudflare Anycast IPs and updates `500ip.txt` in ~15 seconds.*

2. **Scrape & Ingest Fresh Public Proxies**:
   ```bash
   python3 scripts/push_proxyhub.py 5
   ```
   *Scrapes 5 pages from ProxyHub and pushes active proxies directly to `/api/proxies`.*

3. **Check Realtime Gateway Logs & Audit**:
   ```bash
   curl -s http://localhost:13339/api/logs
   curl -s http://localhost:13339/api/audit
   ```
