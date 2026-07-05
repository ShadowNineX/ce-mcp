---
name: ce-mcp
description: Use this skill when an AI agent needs to connect to and operate the ce-mcp Cheat Engine MCP server; select and call its process, memory, scan, symbol, debugger, assembly, address-list, conversion, or Lua MCP tools; use Cheat Engine Lua through execute_lua; or record a local Cheat Engine install path so the agent can consult celua.txt and other CE runtime files.
---

# CE MCP

Use ce-mcp as a Cheat Engine MCP operator guide. Prefer the dedicated MCP tools for normal work, use `execute_lua` only when the exposed tools cannot do the job, and consult the user's installed Cheat Engine Lua reference before writing CE Lua.

Scope: this skill assumes ce-mcp is already installed or running. Its job is to help callers operate the MCP server and local Cheat Engine runtime.

## Start Here

1. Confirm the MCP server is running at the configured Streamable HTTP URL, normally `http://localhost:6300/`.
2. Call `get_plugin_version` and `get_current_process` before acting on memory.
3. If no target is open, use `get_process_list` then `open_process`.
4. Choose a dedicated tool from `references/tool-catalog.md`.
5. Read `references/lua-execution.md` before using `execute_lua` or writing Cheat Engine Lua.

Memory, debugger, Lua, and assembly tools can change target process state. Ask for explicit confirmation before writes, code injection, debugger actions that affect execution, or broad destructive Lua.

## Tool Selection

Read `references/tool-catalog.md` when choosing tools or building a workflow. Prefer the live MCP client tool schemas for exact parameter names, defaults, and required fields when they are available.

Default workflow:

- Process: discover and open the target process first.
- Symbols/modules: enumerate modules and resolve addresses before raw reads.
- Scans: use `memory_scan`, `reset_memory_scan`, and `aob_scan`; avoid hand-written memscan Lua unless the tool surface is missing required behavior.
- Memory: use `read_memory` and `write_memory` for direct reads/writes.
- Code: use disassembly and assembly tools before Auto Assembler or Lua.
- Debugger: use `dbg_*` tools for breakpoints, register reads, stepping, and "find what writes/accesses".
- Lua: use `execute_lua` only as a fallback or for CE APIs not yet exposed as tools.

## Lua Reference And Local CE Path

Cheat Engine installs usually include `celua.txt`, which documents the CE Lua API for that installed build. A common Windows location is:

```text
C:\Program Files\Cheat Engine\celua.txt
```

Do not assume `celua.txt` ships with this skill package. Treat the Cheat Engine install path as the source of truth for Lua definitions.

When the user provides a Cheat Engine install path, or asks to update the skill with a CE path, find and verify the install directly. Check the user-provided path first, then common Windows paths such as `C:\Program Files\Cheat Engine` and `C:\Program Files (x86)\Cheat Engine`. A valid install must contain `celua.txt`; a CE executable, `plugins`, and `ce.runtimeconfig.json` are useful supporting signals.

After verifying the install, edit `references/local-cheat-engine.md` in this skill folder using `references/local-cheat-engine.example.md` as the shape. This file is local-machine state.

Reference priority for CE Lua:

1. `skills/ce-mcp/references/local-cheat-engine.md`, if present, for the configured install path and exact `celua.txt`.
2. The configured install's `celua.txt`.

If no local Cheat Engine path is configured and Lua definitions are needed, ask the user for the Cheat Engine install path before guessing APIs.
