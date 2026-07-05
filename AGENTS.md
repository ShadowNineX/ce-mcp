# Repository Guidelines

## Project Structure & Module Organization

This repository builds `ce-mcp.dll`, a Cheat Engine plugin that hosts an MCP server over Streamable HTTP. The root `CeMCP.sln` and `CeMCP.csproj` target `net10.0-windows`, WPF, and x64.

- `src/`: plugin implementation. `Plugin.cs` wires Cheat Engine menu integration, `McpServer.cs` hosts MCP, `ServerConfig.cs` handles config, and `SchemaTransform.cs` customizes tool schemas.
- `src/Tools/`: MCP tool classes for process, memory, scan, debugger, symbols, Lua, assembly, and address-list operations.
- `src/Views/` and `src/Models/`: WPF configuration UI.
- `CESDK/`: git submodule containing the Cheat Engine Lua API wrapper.
- `skills/ce-mcp/`: distributable AI skill for using and extending this MCP server. Keep it aligned with the codebase.
- `.github/workflows/`: Windows CI for Debug/Release DLL builds and SonarQube analysis.
- Cheat Engine `celua.txt`: installed with Cheat Engine, commonly at `C:\Program Files\Cheat Engine\celua.txt`. Consult the installed file before changing CE/Lua bindings or Lua guidance.

## Build, Test, and Development Commands

```powershell
git submodule update --init --recursive
dotnet restore
dotnet build
dotnet build -c Release
```

`dotnet build` creates `bin/x64/Debug/net10.0-windows/ce-mcp.dll`; Release outputs the same path under `Release`. To test manually, copy the DLL into the Cheat Engine plugins directory, enable it in Cheat Engine 7.6.2+, start the MCP server from the `MCP` menu, and connect a client to `http://localhost:6300/`.

## Coding Style & Naming Conventions

Use C# with nullable reference types enabled and warnings treated as errors. Match existing 4-space indentation, brace style, XML summaries on public wrapper APIs, and concise comments for CE/Lua edge cases. MCP tools should be `public class` types with a private constructor and static methods decorated with `[McpServerTool]`; do not convert them to `static class`. Return structured objects with `success` plus result data or `error`.

## MCP Schema & CE Threading Notes

PR #18 fixed a client-breaking schema issue: optional nullable tool parameters such as `int?`, `string?`, and `bool?` generated JSON schema like `"type": ["integer", "null"]`, which Anthropic-API MCP clients reject with a 400. Register every tool class through `WithToolsAndSchemaTransform<T>()`, not the SDK's plain `WithTools<T>()`, so `SchemaTransform.SchemaCreateOptions` can collapse nullable type arrays to the non-null scalar type. Optional parameters are already omitted from `required`, so this preserves behavior while keeping schemas compatible.

Keep `SchemaTransform` handling for oversized numeric schema keywords. Defaults or bounds such as `ulong.MaxValue` can serialize beyond signed 64-bit and trigger Anthropic converter errors like "int too big to convert"; remove or avoid those schema hints, and prefer signed-64-safe defaults such as `0x7FFFFFFFFFFFFFFF` for scan ranges.

CE SDK, Lua, scanner/foundlist, symbol, disassembler, Auto Assembler, conversion, process, memory, and address-list operations should run on Cheat Engine's main GUI thread. Use `ToolThread.OnMainThread(...)` for new tool bodies unless there is a clear reason to do otherwise; it wraps `Synchronize` and normalizes exceptions. Keep process-attached checks and subsequent CE work inside the same main-thread block when possible to avoid races where the target detaches between the check and operation. `execute_lua` already marshals `LuaExecutor.Execute` through `Synchronize`.

## Skill Maintenance

When changing MCP tools, server registration, tool parameters/defaults, scan behavior, debugger behavior, Lua execution, CE threading assumptions, or installed Cheat Engine path handling, update the repo skill in `skills/ce-mcp/` in the same change. At minimum check:

- `skills/ce-mcp/SKILL.md`: high-level workflows, safety rules, and local Cheat Engine path instructions.
- `skills/ce-mcp/references/tool-catalog.md`: tool names, categories, parameters, defaults, and recommended workflows.
- `skills/ce-mcp/references/lua-execution.md`: Lua API lookup, `execute_lua`, `Synchronize`/main-thread guidance, scanner/foundlist lifecycle, and safety notes.
- `skills/ce-mcp/agents/openai.yaml`: update only when display metadata or default prompt should change.

Do not commit `skills/ce-mcp/references/local-cheat-engine.md`; it is machine-local state that agents may update by editing the Markdown file directly after verifying the user's Cheat Engine install path. After skill edits, run the skill validator if available:

```powershell
python C:\Users\Shadow\.codex\skills\.system\skill-creator\scripts\quick_validate.py skills/ce-mcp
```

`CeMCP.csproj` copies the distributable skill files to the build output beside `ce-mcp.dll` under `skills/ce-mcp/`; the skill must not be embedded into the DLL. Keep `local-cheat-engine.md` and other machine-local files excluded from copied output, and keep GitHub Actions artifact uploads bundling the output skill folder together with the DLL.

## Testing Guidelines

There is no automated test project yet because most behavior requires Cheat Engine at runtime. Always run `dotnet build` before submitting changes. For CE-facing changes, perform a manual plugin smoke test and document which MCP tools or CE menu flows were exercised. For scans, preserve the scan, `WaitTillDone()`, and results initialization sequence.

## Commit & Pull Request Guidelines

Use short, imperative commit subjects, following the existing history style: `Run scans and Lua on CE main thread to stop crashes`, `Bump version to 1.0.1`. Pull requests should describe the changed tool or wrapper, list manual CE verification, link issues when available, and include screenshots for WPF UI changes.

## Security & Runtime Notes

Memory, debugger, Lua, and assembly tools can alter target processes. Keep server defaults loopback-only unless intentionally changing configuration. Persistent config lives under `%APPDATA%\CeMCP\config.json`; `MCP_HOST` and `MCP_PORT` override it.
