# Lua Execution

Use `execute_lua` as the escape hatch for Cheat Engine APIs that are not exposed as dedicated MCP tools. It executes inside Cheat Engine's Lua environment and can access CE functions, forms, memory APIs, debugger APIs, and Auto Assembler helpers.

## Reference Lookup

Before writing CE Lua:

1. If `references/local-cheat-engine.md` exists, read it and use its `celua.txt` path.
2. Otherwise find the local Cheat Engine install directly. Check common paths such as `C:\Program Files\Cheat Engine\celua.txt`, or ask the user for the install path if it cannot be found.
3. Search the installed `celua.txt` for the exact API name and nearby class docs.
4. Prefer the dedicated MCP tools and live MCP tool schemas before writing Lua.

Useful searches:

```powershell
rg -n -C 3 "synchronize|inMainThread|createThread|queue|checkSynchronize|processMessages" "C:\Program Files\Cheat Engine\celua.txt"
rg -n -C 3 "AOBScan|createMemScan|FoundList|waitTillDone|debug_setBreakpoint|autoAssemble" "C:\Program Files\Cheat Engine\celua.txt"
```

## When To Use It

Use dedicated MCP tools first for processes, memory reads/writes, scans, symbols, disassembly, Auto Assembler, address-list entries, and debugger work.

Use `execute_lua` when:

- A CE Lua API exists but no MCP tool exposes it yet.
- You need quick CE UI state inspection.
- You need a small one-off CE Lua query.
- You need functionality documented in the installed Cheat Engine `celua.txt` but not exposed by ce-mcp tools.

Do not use `execute_lua` for routine scans, direct memory writes, code injection, symbol work, disassembly, or address-list edits when a dedicated tool exists.

## Main Thread Rules

Cheat Engine exposes `synchronize(function(...), ...)`, `queue(function(...), ...)`, `checkSynchronize(timeout)`, `inMainThread()`, `processMessages()`, `createThread(...)`, and thread-object `synchronize(...)` in `celua.txt`.

For MCP callers:

- ce-mcp runs `execute_lua` on Cheat Engine's main GUI thread.
- Do not wrap a normal `execute_lua` script in Lua `synchronize(...)`; it is already on CE's main GUI thread.
- Use `return inMainThread()` if you need to confirm the current execution context while debugging.
- Keep `execute_lua` scripts short. Because they run on the main thread, long loops or slow scans can freeze the CE UI.

For Lua that creates background work:

- If you use `createThread`, `createThreadSuspended`, `createThreadNewState`, internet callbacks, or any callback that may run off the main thread, call `thread.synchronize(...)` or global `synchronize(...)` before touching CE UI or CE engine objects.
- Main-thread-only objects include `MainForm`, `AddressList`, forms, controls, timers owned by forms, memory view/disassembler UI, address-list records, scanner/foundlist UI state, and most object methods that mutate CE state.
- Prefer `synchronize(...)` over `queue(...)` when the caller needs the result or needs deterministic ordering.
- Use `queue(...)` only for fire-and-forget UI work. `celua.txt` notes queued calls may not run if the calling thread is freed.
- Use `checkSynchronize(timeout)` only from a main-thread loop that must service queued synchronize calls. Avoid infinite main-thread loops in MCP scripts.
- Avoid `processMessages()` in MCP scripts unless absolutely necessary; CE warns that other Lua scripts or timers can run and mutate local state. If a long UI-bound script must keep CE painted, prefer `processMessagesPaintOnly()`, but the better fix is to make the script smaller.

## Return Values

Use `return` to get data back. `print` writes to CE output and is not a reliable MCP result.

```lua
return getOpenedProcessID()
```

Tables are serialized, so return structured data:

```lua
local pid = getOpenedProcessID()
return {
  pid = pid,
  is64 = targetIs64Bit(),
  process = process,
  mainThread = inMainThread()
}
```

Multiple return values are supported, but a table is usually easier for another agent to consume.

## Safe Script Pattern

Keep scripts bounded and explicit. Use `pcall` so the MCP result can carry a clean error object.

```lua
local ok, result = pcall(function()
  local address = getAddressSafe('game.exe+1234')
  if address == nil then
    return { success = false, error = 'address did not resolve' }
  end

  return {
    success = true,
    address = string.format('%X', address),
    value = readInteger(address),
    mainThread = inMainThread()
  }
end)

if not ok then
  return { success = false, error = tostring(result) }
end

return result
```

## Scanner And Object Lifetime

Prefer ce-mcp scan tools for `MemScan` workflows. They already handle the fragile sequence: deinitialize stale results, scan, `WaitTillDone()`, then initialize results.

If Lua must use CE scan APIs:

- `AOBScan(...)` returns a StringList; copy the addresses you need, then free the list.
- `createMemScan(...)` returns a MemScan object; call `waitTillDone()` after `firstScan`, `nextScan`, or `scan`.
- `FoundList.initialize()` must happen after scanning is complete, and `FoundList.deinitialize()` should release result access when done.
- Do not keep FoundList objects across next scans unless the CE docs for that exact workflow say it is safe.
- Keep returned result sets small. Return counts and first matches rather than massive arrays.

## Safety Rules

- Ask before memory writes, `autoAssemble`, debugger breakpoints that alter execution, file operations, process control, or Lua that changes CE settings.
- Avoid `os.execute`, arbitrary file deletion, network calls, or persistence unless the user explicitly requests it.
- Do not call `resetLuaState()` casually; `celua.txt` notes it creates a new Lua state without destroying the old one.
- If a Lua script fails, report the exact error and the installed `celua.txt` path checked.
