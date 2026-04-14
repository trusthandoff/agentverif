# LangChain Integration

`agentverif-sign` ships a ready-to-use `StructuredTool` so any LangChain
agent can verify signed AI-agent packages at runtime.

## Requirements

```bash
pip install agentverif-sign langchain-core
# or the full meta-package:
pip install agentverif-sign langchain
```

Both `langchain-core` (≥ 0.3) and the full `langchain` package are supported.
The tool gracefully degrades to `None` if neither is installed.

---

## Quick start

```python
from agentverif_sign.langchain_tool import verify_tool

# Verify by license ID (queries the registry)
result = verify_tool.invoke({"license_id": "INDIE-a1b2c3"})
print(result)
# ✅ VERIFIED — Signature valid. Tier: indie | ID: INDIE-a1b2c3 | https://verify.agentverif.com/INDIE-a1b2c3

# Verify a local zip file
result = verify_tool.invoke({"zip_path": "/path/to/my_agent.zip"})
print(result)
# ✅ VERIFIED — Signature valid. Tier: pro | ID: PRO-xyz789 | https://verify.agentverif.com/PRO-xyz789

# Offline check (no registry call)
result = verify_tool.invoke({"zip_path": "/path/to/my_agent.zip", "offline": True})
print(result)
# ⚠ UNREGISTERED — Signature valid locally; registry not checked | ...
```

---

### Sign your agent

```python
from agentverif_sign.langchain_tool import sign_tool

result = sign_tool.run("./my-agent.zip")
# ✅ SIGNED — agentverif certified
# License: AC-XXXX-XXXX
```

### Use both in one agent

```python
from agentverif_sign.langchain_tool import verify_tool, sign_tool
from langchain.agents import initialize_agent, AgentType

agent = initialize_agent(
    tools=[verify_tool, sign_tool],
    llm=llm,
    agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
)
```

---

## Use inside a LangChain agent

```python
from langchain_core.language_models.chat_models import BaseChatModel
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate

from agentverif_sign.langchain_tool import verify_tool

# verify_tool is a StructuredTool — pass it in the tools list directly
tools = [verify_tool]

prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a helpful assistant. Verify agent packages when asked."),
    ("human", "{input}"),
    ("placeholder", "{agent_scratchpad}"),
])

# llm = <any BaseChatModel with tool-calling support>
agent = create_tool_calling_agent(llm, tools, prompt)
executor = AgentExecutor(agent=agent, tools=tools, verbose=True)

executor.invoke({"input": "Is the agent with license INDIE-a1b2c3 verified?"})
```

---

## Check if LangChain is available

```python
from agentverif_sign.langchain_tool import LANGCHAIN_AVAILABLE, verify_tool

if not LANGCHAIN_AVAILABLE:
    raise RuntimeError("Install langchain-core: pip install langchain-core")

print(verify_tool.name)         # agentverif_verify
print(verify_tool.description)  # Verify a signed AI-agent package …
print(verify_tool.args)         # {'license_id': …, 'zip_path': …, 'offline': …}
```

---

## Tool schema

| Argument | Type | Default | Description |
|---|---|---|---|
| `license_id` | `str` | `""` | License ID from a signed package (e.g. `INDIE-a1b2c3`) |
| `zip_path` | `str` | `""` | Local path to a signed `.zip` agent file |
| `offline` | `bool` | `False` | Skip remote registry check |

Supply **either** `license_id` **or** `zip_path`.  
If both are given, `zip_path` takes precedence.

---

## Possible return values

| Prefix | Meaning |
|---|---|
| `✅ VERIFIED` | Hash matches and registry confirms the signature is valid |
| `⚠ UNREGISTERED` | Hash is intact but not in the registry (offline or unsigned remotely) |
| `⚠ MODIFIED` | Package contents changed after signing |
| `❌ REVOKED` | License has been revoked |
| `❌ UNSIGNED` | No `SIGNATURE.json` found in the zip |
| `❌ Registry error: …` | Could not reach the registry |

---

## Direct function (no LangChain dependency)

The underlying function can be called without LangChain at all:

```python
from agentverif_sign.langchain_tool import run_verify

status = run_verify(zip_path="/path/to/agent.zip")
print(status)
```
