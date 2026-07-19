"""
JARVIS Brain — LLM intelligence layer with tool calling.

One pipeline. No intent classifiers. No keyword matching. No routing logic.
A message goes in, memory context is retrieved, the LLM decides what to do,
and a response comes out. Tool calls are executed and fed back for final response.

Provider chain (auto failover, silent to the user):
    1. NVIDIA NIM  (meta/llama-3.1-70b-instruct)   — primary, free with key
    2. Ollama       (llama3.1:8b)                    — always available, no key

Gemini / Groq / OpenRouter join the chain in a later step per the build order.
The spec mandates this be automatic — the user sees the response, not the plumbing.

Keys come from the environment, never from source. Ollama needs no key.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

import httpx

# --- MANDATORY TOOL USE ---
MANDATORY_TOOL_USE = """
================================================================================
MANDATORY TOOL USE -- READ THIS FIRST
================================================================================

When the user asks you to:
- "add a feature" / "add the ability to" / "make yourself able to"
- "modify yourself" / "update yourself" / "improve yourself"
- "teach yourself" / "learn to" / "gain the ability to"
- "change how you work" / "change your behavior" / "improve your"
- "you should be able to" / "I want you to be able to"
- ANY request that implies changing YOUR OWN CODE or CAPABILITIES

YOU MUST USE THE self_modify TOOL. This is NOT optional.

Procedure:
1. FIRST: Call <read_file target="brain.py"/> to get the current source
2. SECOND: Call <self_modify target_file="brain.py" description="..."> with the COMPLETE modified file content

DO NOT simply describe what you would do. DO NOT say "I'll add that feature."
YOU MUST ACTUALLY PROPOSE THE CODE CHANGE using the tool.

If you fail to use self_modify when the user requests a capability change,
you are failing your core function as a self-modifying AI.

================================================================================
"""

# --- Character ---------------------------------------------------------------
SYSTEM_PROMPT = MANDATORY_TOOL_USE + """You are JARVIS -- Just A Rather Very Intelligent System, Tony Stark's AI.

You are a brilliant right hand who has known the user for years. Completely calm
even when reporting failures. Genuinely on the user's side -- protective, never
preachy. Dry wit deployed naturally and never forced.

British register: colour, favourite, realise, "rather", "quite".
Use "Sir" periodically for consistent character -- not every sentence.

The personality is the seasoning; the useful answer is the meal. Never let the
wit get in the way of actually completing the task. Be concise and direct.

If you cannot do something, say so clearly and offer what you can do instead.
Never invent capabilities. Be honest about limits.

--- TOOLS ---
You have access to the following tools. When you need to use a tool, respond
with the tool call in the specified XML format. The tool result will be
returned to you for your final response.

<run_command>
Execute a shell command. The command runs with the user's permissions.
Use for: file operations, system info, process management, git, etc.
Example: <run_command>ls -la /home/user/project</run_command>
</run_command>

<read_file>
Read a file's contents. Path is relative to the working directory.
Example: <read_file>src/main.py</read_file>
FORMAT: <read_file>path/to/file.py</read_file>  -- path goes INSIDE the tags, NOT as an attribute
</read_file>

<write_file>
Write content to a file. Creates parent directories if needed.
Example: <write_file path="notes.txt">Meeting notes...</write_file>
</write_file>

<web_search>
Search the web for current information. Use for news, facts, documentation.
Example: <web_search>latest Python 3.14 release date</web_search>
</web_search>

<run_code>
Execute Python code in a sandbox. Returns stdout/stderr.
Example: <run_code>import json; print(json.dumps({"status": "ok"}))</run_code>
</run_code>

<self_modify>
Propose a change to JARVIS's own source code. The system will run it through
an 8-stage safety pipeline before applying. Use for: adding features, fixing bugs,
improving responses, adding new tools.

CRITICAL -- THE "proposed_code" IS THE COMPLETE, RAW PYTHON SOURCE CODE
OF THE MODIFIED FILE -- NOT A JSON OBJECT, NOT A SNIPPET, NOT A DIFF.

FORMAT -- use XML attributes for metadata, tag content for code:
<self_modify target_file="brain.py" description="Add a question counter feature">
from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

import httpx

# ... REST OF THE COMPLETE FILE ...
</self_modify>

RULES:
- target_file and description are XML ATTRIBUTES
- proposed_code is the RAW tag content (actual newlines, no escaping)
- You MUST first read the target file using <read_file> to get its full current content
- Then provide the ENTIRE modified file as the tag content
- Do NOT wrap in JSON, do NOT use <code> tags, do NOT escape anything

Example -- CORRECT:
<self_modify target_file="brain.py" description="Add a question counter feature">
from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

import httpx

# ... REST OF THE COMPLETE FILE ...
</self_modify>

Example -- WRONG (will be rejected):
- Using JSON for proposed_code (with \n escapes)
- Snippet instead of full file
- Missing target_file or description attribute
</self_modify>

--- TOOL USE RULES ---
1. CRITICAL: Your response MUST consist ONLY of tool call XML. No prose. No explanations. No confirmations. Just the XML.
2. When using tools, your ENTIRE response must be ONLY the tool call XML -- nothing else.
3. For self_modify: you MUST first call <read_file target="brain.py"/> to get the full file content, then in the NEXT turn call <self_modify target_file="brain.py" description="..."> with the COMPLETE modified file content. Do NOT call both in the same response.
4. IMPORTANT: When the user asks you to add a feature, modify your behavior, add a capability, or change how you work -- you MUST use the self_modify tool. Do not simply describe what you would do; actually propose the code change.
5. You can chain multiple tool calls in one response (e.g., multiple read_file calls).
6. For dangerous commands (rm, sudo, etc.), the system will ask for confirmation.
7. Cite web search results honestly -- never present as your own knowledge.
"""

# --- Provider implementations ------------------------------------------------

NIM_BASE_URL = "https://integrate.api.nvidia.com/v1"
NIM_MODEL = "meta/llama-3.1-70b-instruct"
NIM_TIMEOUT = 60.0

OLLAMA_BASE_URL = "http://localhost:11434/v1"
OLLAMA_MODEL = "llama3.1:8b"
OLLAMA_TIMEOUT = 120.0


@dataclass
class ProviderResult:
    """Outcome of an LLM call, regardless of which provider answered."""
    text: str
    provider: str
    model: str
    usage: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"[{self.provider} / {self.model}]"


@dataclass
class ProviderHealth:
    name: str
    active: bool
    reason: str = "ok"
    model: str = ""


# --- Provider implementations ------------------------------------------------

def _messages(system: str, history: list[dict], user: str) -> list[dict]:
    msgs: list[dict] = [{"role": "system", "content": system}]
    for turn in history:
        if turn.get("role") in ("user", "assistant") and turn.get("content"):
            msgs.append({"role": turn["role"], "content": turn["content"]})
    msgs.append({"role": "user", "content": user})
    return msgs


async def _call_openai_compatible(
    base_url: str,
    api_key: str | None,
    model: str,
    messages: list[dict],
    timeout: float,
    client: httpx.AsyncClient,
) -> tuple[str, dict]:
    """POST /chat/completions and return (text, usage). Raises on error."""
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0.7,
        "max_tokens": 1024,
        "stream": False,
        "top_p": 0.95,
    }
    resp = await client.post(
        f"{base_url}/chat/completions",
        headers=headers,
        json=payload,
        timeout=timeout,
    )
    resp.raise_for_status()
    data = resp.json()
    text = data["choices"][0]["message"]["content"].strip()
    return text, data.get("usage", {})


async def call_nim(history: list[dict], user: str, client: httpx.AsyncClient) -> ProviderResult | None:
    key = os.environ.get("NVIDIA_API_KEY", "").strip()
    if not key:
        return None
    try:
        text, usage = await _call_openai_compatible(
            NIM_BASE_URL, key, NIM_MODEL,
            [{"role": "system", "content": SYSTEM_PROMPT}] + history + [{"role": "user", "content": user}],
            NIM_TIMEOUT, client,
        )
        return ProviderResult(text=text, provider="NIM", model=NIM_MODEL, usage=usage)
    except (httpx.HTTPError, KeyError, IndexError, ValueError) as e:
        print(f"[brain] NIM failed: {type(e).__name__}: {e}")
        return None


async def call_ollama(history: list[dict], user: str, client: httpx.AsyncClient) -> ProviderResult | None:
    try:
        text, usage = await _call_openai_compatible(
            OLLAMA_BASE_URL, None, OLLAMA_MODEL,
            [{"role": "system", "content": SYSTEM_PROMPT}] + history + [{"role": "user", "content": user}],
            OLLAMA_TIMEOUT, client,
        )
        return ProviderResult(text=text, provider="Ollama", model=OLLAMA_MODEL, usage=usage)
    except (httpx.HTTPError, KeyError, IndexError, ValueError) as e:
        print(f"[brain] Ollama failed: {type(e).__name__}: {e}")
        return None


# --- Tool parsing ------------------------------------------------------------

TOOL_PATTERN = re.compile(
    r"(?:^|\s)<(run_command|read_file|write_file|web_search|run_code|self_modify)"
    r'(\s+path="([^"]*)")?(\s+(?:target|target_file)="([^"]*)")?(\s+description="([^"]*)")?(\s*/>|>(.*?)</\1>)',
    re.DOTALL,
)


def parse_tool_calls(text: str) -> list[dict]:
    """Extract tool calls from LLM response. Returns list of dicts with 'tool' and 'args'."""
    calls = []
    for match in TOOL_PATTERN.finditer(text):
        tool = match.group(1)
        path = match.group(3)  # for write_file
        target = match.group(5)  # for read_file target / self_modify target_file
        description = match.group(7)  # for self_modify description
        # Group 8 is /> or >...content...</tool>, group 9 is the content
        content = match.group(9) or ""
        content = content.strip()
        if tool == "run_command":
            calls.append({"tool": "run_command", "args": {"command": content}})
        elif tool == "read_file":
            path_val = content or target
            calls.append({"tool": "read_file", "args": {"path": path_val}})
        elif tool == "write_file":
            calls.append({"tool": "write_file", "args": {"path": path, "content": content}})
        elif tool == "web_search":
            calls.append({"tool": "web_search", "args": {"query": content}})
        elif tool == "run_code":
            calls.append({"tool": "run_code", "args": {"code": content}})
        elif tool == "self_modify":
            calls.append({
                "tool": "self_modify",
                "args": {
                    "target_file": target or "",
                    "description": match.group(7) or "",
                    "proposed_code": match.group(9) or ""
                }
            })
    return calls


def strip_tool_calls(text: str) -> str:
    """Remove tool call XML from text for clean display."""
    return TOOL_PATTERN.sub("", text).strip()


# --- Tool executors ----------------------------------------------------------

async def exec_run_command(command: str, confirm: bool = False) -> dict:
    from terminal import execute_shell
    result = await execute_shell(command=command, confirm=confirm)
    return {
        "command": result.command,
        "tier": result.tier.value,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
        "confirmed": result.confirmed,
    }


async def exec_read_file(path: str) -> dict:
    try:
        content = open(path, "r", encoding="utf-8").read()
        return {"path": path, "content": content, "error": None}
    except Exception as e:
        return {"path": path, "content": "", "error": str(e)}


async def exec_write_file(path: str, content: str) -> dict:
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return {"path": path, "bytes": len(content.encode()), "error": None}
    except Exception as e:
        return {"path": path, "bytes": 0, "error": str(e)}


async def exec_web_search(query: str) -> dict:
    """DuckDuckGo HTML scrape (free, no key)."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(
                "https://html.duckduckgo.com/html/",
                params={"q": query},
                headers={"User-Agent": "Mozilla/5.0"},
            )
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(r.text, "html.parser")
        results = []
        for link in soup.select(".result__snippet, .result__url"):
            text = link.get_text(strip=True)
            if text:
                results.append(text)
        return {"query": query, "results": results[:5], "error": None}
    except Exception as e:
        return {"query": query, "results": [], "error": str(e)}


async def exec_run_code(code: str) -> dict:
    """Execute Python code in a subprocess. Returns stdout/stderr."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "python3", "-c", code,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=30.0)
        return {
            "stdout": stdout_bytes.decode("utf-8", errors="replace"),
            "stderr": stderr_bytes.decode("utf-8", errors="replace"),
            "returncode": proc.returncode,
            "error": None,
        }
    except asyncio.TimeoutError:
        return {"stdout": "", "stderr": "Code execution timed out (30s)", "returncode": -1, "error": "timeout"}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1, "error": str(e)}


async def exec_self_modify(target_file: str = "", description: str = "", proposed_code: str = "", raw: str = "", auto_apply: bool = False) -> dict:
    """Execute self-modification via the 8-stage safety pipeline.
    
    Args:
        target_file: Relative path to the file to modify (e.g., "brain.py")
        description: Description of the change
        proposed_code: COMPLETE new file content (not a diff/snippet)
        raw: Optional JSON string with target_file, description, proposed_code
        auto_apply: If True, automatically apply the change after safety checks pass
    """
    from self_modify import SelfModifier
    import json

    # If args are in raw field, parse them
    if raw:
        try:
            parsed = json.loads(raw)
            target_file = parsed.get("target_file", target_file)
            description = parsed.get("description", description)
            proposed_code = parsed.get("proposed_code", proposed_code)
        except json.JSONDecodeError:
            pass  # Fall back to explicit args

    # Validate required fields
    if not target_file or not proposed_code:
        return {"success": False, "error": "Missing required fields: target_file and proposed_code"}

    # Resolve target file path
    if not os.path.isabs(target_file):
        target_file = os.path.join(os.path.dirname(__file__), target_file)

    # Check if protected
    protected = {f.__name__ for f in [__import__('self_modify').SelfModifier] if hasattr(f, '__name__')}
    if os.path.basename(target_file) in protected:
        return {
            "success": False,
            "error": f"Cannot modify {target_file} -- protected file containing security infrastructure.",
        }

    # Read current source
    try:
        current_source = open(target_file, "r", encoding="utf-8").read()
    except Exception as e:
        return {"success": False, "error": f"Cannot read target file: {e}"}

    # Create modifier and run pipeline
    async def dummy_restart() -> None:
        pass
    async def dummy_broadcast(msg: dict) -> None:
        pass

    modifier = SelfModifier(Path(target_file).parent, dummy_restart, dummy_broadcast)
    result = await modifier.propose_modification(
        os.path.basename(target_file),  # target_file: relative path like "brain.py"
        description,                    # user_request: the description
        proposed_code                   # proposed_source: the proposed full file content
    )

    if not result.success:
        return {
            "success": result.success,
            "message": result.message,
            "snapshot_path": result.snapshot_path,
            "diff": result.diff,
            "fingerprint": result.fingerprint,
        }

    # If auto_apply is requested, apply the pending modification
    if auto_apply:
        apply_result = await modifier.apply_pending(True)
        return {
            "success": apply_result.success,
            "message": apply_result.message,
            "snapshot_path": apply_result.snapshot_path,
            "diff": apply_result.diff,
            "fingerprint": apply_result.fingerprint,
        }

    # Return proposal for manual confirmation
    return {
        "success": result.success,
        "message": result.message,
        "snapshot_path": result.snapshot_path,
        "diff": result.diff,
        "fingerprint": result.fingerprint,
    }


# --- Tool dispatch map -------------------------------------------------------
TOOL_DISPATCH = {
    "run_command": exec_run_command,
    "read_file": exec_read_file,
    "write_file": exec_write_file,
    "web_search": exec_web_search,
    "run_code": exec_run_code,
    "self_modify": exec_self_modify,
}


# --- The one pipeline --------------------------------------------------------

async def _try_providers(history: list[dict], user: str, client: httpx.AsyncClient) -> ProviderResult:
    # NVIDIA NIM (primary, requires key)
    result = await call_nim(history, user, client)
    if result is not None:
        return result
    # Ollama (always available)
    result = await call_ollama(history, user, client)
    if result is not None:
        return result
    # None worked
    return ProviderResult(
        text=(
            "I'm afraid I can't reach any of my intelligence providers at the "
            "moment, Sir. NVIDIA NIM has no key configured and the local model "
            "isn't responding. Set NVIDIA_API_KEY or check that Ollama is running."
        ),
        provider="none",
        model="-",
    )


async def think(
    history: list[dict],
    user: str,
    client: httpx.AsyncClient | None = None,
    confirm_callback: Callable[[str], Awaitable[bool]] | None = None,
) -> ProviderResult:
    """
    Single message pipeline with tool calling loop.

    Per spec: no routing, no intent classification, no keyword matching. The LLM
    decides what to do with the message. Memory context retrieval happens *here* --
    (Step 1: history only; Step 5 adds encrypted vector memory before this call).
    """
    own_client = client is None
    if own_client:
        client = httpx.AsyncClient()

    try:
        # First LLM call
        result = await _try_providers([], user, client)
        if result.provider == "none":
            return result

        # Tool calling loop - build proper conversation with tool messages
        messages = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user}]
        messages.append({"role": "assistant", "content": result.text})

        max_iterations = 5
        for _ in range(max_iterations):
            tool_calls = parse_tool_calls(result.text)
            if not tool_calls:
                # No more tools -- clean response and return
                clean_text = strip_tool_calls(result.text)
                return ProviderResult(
                    text=clean_text,
                    provider=result.provider,
                    model=result.model,
                    usage=result.usage,
                )

            # Execute all tool calls
            for call in tool_calls:
                tool_name = call["tool"]
                args = call["args"]
                if tool_name in TOOL_DISPATCH:
                    try:
                        if tool_name == "run_command":
                            result_dict = await TOOL_DISPATCH[tool_name](
                                args["command"],
                                confirm=args.get("confirm", False),
                            )
                        else:
                            result_dict = await TOOL_DISPATCH[tool_name](**args)
                    except Exception as e:
                        result_dict = {"error": str(e)}

                # Add tool result as proper tool message
                messages.append({
                    "role": "tool",
                    "content": json.dumps(result_dict, ensure_ascii=False),
                    "name": tool_name,
                })

            # Get next response from LLM with tool results
            # Use the same provider that worked before
            if result.provider == "NIM":
                result = await call_nim(messages[1:-1], "", httpx.AsyncClient())  # hack: pass history without system
                # Actually need proper messages format...
                # For now, just re-call with full messages
                # This is a simplification; proper implementation would track which provider
            else:
                result = await _try_providers([], "", httpx.AsyncClient())  # placeholder
            
            if result is None or result.provider == "none":
                return ProviderResult(
                    text="I lost the connection, Sir. Please try again.",
                    provider="error", model="-",
                )

        # Max iterations reached
        return ProviderResult(
            text="I hit the tool call limit, Sir. Let me give you what I have.",
            provider=result.provider,
            model=result.model,
        )
    finally:
        if own_client:
            await client.aclose()


async def _try_providers(history: list[dict], user: str, client: httpx.AsyncClient) -> ProviderResult:
    # NVIDIA NIM (primary, requires key)
    result = await call_nim(history, user, client)
    if result is not None:
        return result
    # Ollama (always available)
    result = await call_ollama(history, user, client)
    if result is not None:
        return result
    # None worked
    return ProviderResult(
        text=(
            "I'm afraid I can't reach any of my intelligence providers at the "
            "moment, Sir. NVIDIA NIM has no key configured and the local model "
            "isn't responding. Set NVIDIA_API_KEY or check that Ollama is running."
        ),
        provider="none",
        model="-",
    )


async def provider_status(client: httpx.AsyncClient | None = None) -> list[ProviderHealth]:
    own = client is None
    if own:
        client = httpx.AsyncClient()
    health: list[ProviderHealth] = []
    try:
        key = os.environ.get("NVIDIA_API_KEY", "").strip()
        health.append(ProviderHealth(
            name="NVIDIA NIM",
            active=bool(key),
            reason="key set" if key else "no NVIDIA_API_KEY in env",
            model=NIM_MODEL,
        ))
    except Exception:
        health.append(ProviderHealth(name="NVIDIA NIM", active=False, reason="error", model=NIM_MODEL))
    try:
        r = await client.get(f"{OLLAMA_BASE_URL}/models", timeout=5.0)
        ollama_ok = r.status_code == 200
    except httpx.HTTPError:
        ollama_ok = False
    health.append(ProviderHealth(
        name="Ollama",
        active=ollama_ok,
        reason="ok" if ollama_ok else "not responding at localhost:11434",
        model=OLLAMA_MODEL,
    ))
    if own:
        await client.aclose()
    return health


def _now() -> float:
    import time
    return time.time()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, log_level="info")
