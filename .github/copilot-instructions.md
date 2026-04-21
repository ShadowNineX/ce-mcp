# Project Guidelines

## Project Overview

Cheat Engine MCP Server — a C# plugin that exposes Cheat Engine functionality as MCP tools over SSE (Server-Sent Events) using the official [Model Context Protocol C# SDK](https://github.com/modelcontextprotocol/csharp-sdk).

**Key Architecture**:
- **MCP SSE Server**: ASP.NET Core app on `http://127.0.0.1:6300` with SSE at `/sse`
- **CE Plugin Host**: Runs inside Cheat Engine process, manages server lifecycle via menu
- **CESDK Submodule**: C# wrapper for CE's Lua API (git submodule dependency)
- **Single DLL**: All dependencies embedded, copy to CE plugins folder to deploy

## Cheat Engine Lua API Reference

The full CE Lua API documentation is at `C:\Program Files\Cheat Engine\celua.txt`. Always consult this file when:
- Adding new CESDK wrapper methods or tools
- Verifying correct Lua function names, parameters, and return types
- Understanding CE object models (MemScan, FoundList, AddressList, MemoryRecord, etc.)

## Build and Test

```bash
# Initialize submodule (first time only)
git submodule update --init --recursive

# Build Debug
dotnet build

# Build Release
dotnet build -c Release
```

**Deploy**: Copy `ce-mcp.dll` from `bin/x64/Debug/net10.0-windows/` (or Release) to Cheat Engine plugins directory, enable in CE, use "MCP" → "Start MCP Server" menu.

**Requirements**: .NET 10.0 SDK, CE 7.6.2+, ASP.NET Core 10.0 runtime. CE must have `ce.runtimeconfig.json` set to .NET 10.0 (see README).

## Architecture

### Core Components

- **Plugin.cs** — Main CE plugin entry point (`McpPlugin : CheatEnginePlugin`). Manages MCP server lifecycle, registers Lua functions for CE menu integration (`toggle_mcp_server`, `show_mcp_config`), provides WPF config UI. Handles assembly resolution for WPF components.
- **McpServer.cs** — MCP SSE server using `ModelContextProtocol.AspNetCore`. Registers all tools via `WithTools<T>()`, resources via `WithResources<T>()`, and maps endpoints with `MapMcp()`. Runs ASP.NET Core with minimal logging in background task.
- **ServerConfig.cs** — Configuration management (host/port/name). Loads from `%APPDATA%\CeMCP\config.json` with env var overrides (`MCP_HOST`, `MCP_PORT`). Uses source-generated JSON serialization.
- **ThemeHelper.cs** — Cross-platform dark mode detection (Windows registry, macOS `defaults`, Linux GTK settings)

### Tools (`src/Tools/`)

All tools use `[McpServerToolType]` on the class and `[McpServerTool(Name = "tool_name")]` + `[Description]` on methods. Tools are `public class` with a `private Constructor() {}` and static methods (not `static class` — required for MCP SDK DI). Each returns anonymous objects with `success` boolean and either result data or `error` message.

- **ProcessTool** — Process and thread management (list/open processes, get current process ID)
- **MemoryTool** — Memory read and write (bytes, int8/16/32/64, float, double, string, AOB patterns)
- **ScanTool** — Memory scanning (first scan, next scan, reset, AOB scan) using MemScan/FoundList
- **AssemblyTool** — Disassembly and address resolution (symbol lookups)
- **AutoAssemblyTool** — Single-instruction assembly, Auto Assembler script execution and syntax checking
- **MemoryViewTool** — Memory view operations: disassemble ranges, navigate code backwards, enumerate memory regions, query protections, set comments
- **SymbolTool** — Symbol/module management: enumerate loaded modules, symbol lookup, enable Windows/kernel symbols, pointer size management
- **AddressListTool** — Cheat table CRUD operations (get/add/update/delete/clear records)
- **LuaExecutionTool** — Execute arbitrary Lua scripts in CE with stack management
- **ConversionTool** — String format conversion (MD5, ANSI/UTF8)

### Resources (`src/Resources/`)

> **Not yet implemented** — `src/Resources/` does not exist yet. Resources use `[McpServerResourceType]` on class and `[McpServerResource(UriTemplate = "scheme://path")]` + `[Description]` on methods. Resources are read-only state/data (vs tools which perform actions). Return JSON strings.

### SDK Layer (`CESDK/`)

Git submodule — C# wrapper around Cheat Engine's Lua API. Key classes: `MemoryAccess`, `Process`, `AOBScanner`, `Assembler`, `Disassembler`, `AddressResolver`, `MemScan`, `FoundList`, `AddressList`, `ThreadList`, `Converter`, `Speedhack`, `Debugger`, `SymbolWaiter`, `SymbolManager`, `MemoryRegions`.

### Views (`src/Views/`)

- **ConfigWindow.xaml/.cs** — WPF config window. Supports dark/light theme via `ThemeHelper`. Runs in STA thread with dispatcher for cross-thread UI updates.

## Adding New Tools

1. Create a new file in `src/Tools/` with `[McpServerToolType]` class attribute
2. Add static methods with `[McpServerTool(Name = "tool_name")]` and `[Description("...")]`
3. Use `[Description]` on parameters for MCP schema generation
4. Return anonymous objects: `new { success = true, ... }` or `new { success = false, error = "..." }`
5. Register in `McpServer.cs` via `.WithTools<Tools.YourTool>()`
6. Consult `C:\Program Files\Cheat Engine\celua.txt` for correct Lua function signatures
7. Use `CESDK.Synchronize(() => { ... })` for AddressList/UI operations that must run on CE's main thread

Example:
```csharp
[McpServerToolType]
public class MyTool
{
    private MyTool() { }

    [McpServerTool(Name = "my_action"), Description("Does something useful")]
    public static object MyAction([Description("Input param")] string input)
    {
        try {
            // Use Synchronize for AddressList operations
            var result = CESDK.Synchronize(() => {
                var al = new AddressList();
                return al.Count;
            });
            return new { success = true, result };
        } catch (Exception ex) {
            return new { success = false, error = ex.Message };
        }
    }
}
```

## Adding New Resources

1. Create a new file in `src/Resources/` with `[McpServerResourceType]` class attribute
2. Add static methods with `[McpServerResource(UriTemplate = "scheme://path", Title = "...")]` and `[Description]`
3. Return JSON string (use `System.Text.Json.JsonSerializer.Serialize`)
4. Register in `McpServer.cs` via `.WithResources<Resources.YourResource>()`

Example:
```csharp
[McpServerResourceType]
public static class MyResource
{
    [McpServerResource(UriTemplate = "mydata://info", Title = "My Data"),
     Description("Returns my data")]
    public static string GetInfo()
    {
        return JsonSerializer.Serialize(new { data = "value" });
    }
}
```

## Code Style

- C# with nullable reference types enabled, `TreatWarningsAsErrors`
- Target: `net10.0-windows`, WPF enabled, x64 platform
- Tools are `public class` (not `static class`) with a `private Constructor() { }` and static methods — required by MCP SDK for DI compatibility
- Wrap CE SDK calls in try-catch, always return structured response objects
- Use proper Lua stack management (`GetTop`, `Pop`) when interacting with Lua

## Important Notes

- **Lua stack**: Always clean up with `lua.Pop()` calls after reading values
- **CE thread safety**: Use `CESDK.Synchronize()` for operations that must run on CE's main thread (e.g., AddressList operations)
- **Memory scanning**: Requires scan → `WaitTillDone()` → `foundList.Initialize()` sequence
- **Dark mode**: UI adapts via Windows registry check (`ThemeHelper.IsInDarkMode()`)
- Default server: `http://127.0.0.1:6300` with MCP SSE at `/sse`
- **CE Lua API docs**: [celua.txt](../celua.txt) (workspace root copy) or `C:\Program Files\Cheat Engine\celua.txt` — the authoritative reference for all CE Lua functions, objects, and their parameters
- **WPF Assembly Resolution**: Plugin.cs registers AssemblyResolve handler to fix WPF's `Application.LoadComponent` in CE host process
- **Config location**: `%APPDATA%\CeMCP\config.json` for persistent settings, env vars `MCP_HOST`/`MCP_PORT` override

## Project Configuration

- **Target**: `net10.0-windows` with WPF, x64 platform only
- **Self-contained**: All dependencies embedded in single DLL
- **Roll-forward**: `Major` to find available ASP.NET Core runtime
- **Package**: `ModelContextProtocol.AspNetCore` v0.8.0-preview.1
- **Assembly name**: `ce-mcp.dll` for CE plugin loader
- **Output path**: `bin/x64/Debug/net10.0-windows/ce-mcp.dll` (or Release)

## GitHub Actions

- **build-dlls.yml** — Builds Debug and Release DLLs on push/PR, uploads as artifacts
- **sonarqube.yml** — SonarQube code quality analysis workflow

## CESDK Submodule

The `CESDK/` directory is a git submodule providing the Cheat Engine SDK wrapper library:

- **Core**: `CESDK.cs`, `CheatEnginePlugin.cs`, `PluginContext.cs`
- **Lua**: `LuaNative.cs` (low-level C API bindings)
- **Classes**: `MemoryAccess`, `Process`, `AOBScanner`, `Assembler`, `Disassembler`, `AddressResolver`, `MemScan`, `FoundList`, `AddressList`, `ThreadList`, `Converter`, `Speedhack`, `Debugger`, `SymbolWaiter`, `SymbolManager`, `MemoryRegions`, `LuaLogger`, `LuaExecutor`
- **Utils**: `LuaUtils.cs` (helper functions for Lua stack operations)

Plugin pattern: inherit `CheatEnginePlugin`, implement `Name`/`OnEnable()`/`OnDisable()`, access Lua via `PluginContext.Lua`.
