# Repository Guidelines

## Project Structure & Module Organization

This repository builds `ce-mcp.dll`, a Cheat Engine plugin that hosts an MCP server over Streamable HTTP. The root `CeMCP.sln` and `CeMCP.csproj` target `net10.0-windows`, WPF, and x64.

- `src/`: plugin implementation. `Plugin.cs` wires Cheat Engine menu integration, `McpServer.cs` hosts MCP, `ServerConfig.cs` handles config, and `SchemaTransform.cs` customizes tool schemas.
- `src/Tools/`: MCP tool classes for process, memory, scan, debugger, symbols, Lua, assembly, and address-list operations.
- `src/Views/` and `src/Models/`: WPF configuration UI.
- `CESDK/`: git submodule containing the Cheat Engine Lua API wrapper.
- `.github/workflows/`: Windows CI for Debug/Release DLL builds and SonarQube analysis.
- `celua.txt`: local Cheat Engine Lua API reference. Consult it before changing CE bindings.

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

## Testing Guidelines

There is no automated test project yet because most behavior requires Cheat Engine at runtime. Always run `dotnet build` before submitting changes. For CE-facing changes, perform a manual plugin smoke test and document which MCP tools or CE menu flows were exercised. For scans, preserve the scan, `WaitTillDone()`, and results initialization sequence.

## Commit & Pull Request Guidelines

Use short, imperative commit subjects, following the existing history style: `Run scans and Lua on CE main thread to stop crashes`, `Bump version to 1.0.1`. Pull requests should describe the changed tool or wrapper, list manual CE verification, link issues when available, and include screenshots for WPF UI changes.

## Security & Runtime Notes

Memory, debugger, Lua, and assembly tools can alter target processes. Keep server defaults loopback-only unless intentionally changing configuration. Persistent config lives under `%APPDATA%\CeMCP\config.json`; `MCP_HOST` and `MCP_PORT` override it.
