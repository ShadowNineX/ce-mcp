# Tool Catalog

This catalog summarizes the ce-mcp tools exposed by the MCP server. Prefer the live MCP client tool schemas for exact parameter names, defaults, and required fields when they are available.

## Process

- `get_plugin_version`: Return plugin version, server name, and server URL metadata.
- `get_process_list`: List running processes.
- `open_process`: Open a process by ID or name in Cheat Engine.
- `get_current_process`: Report the process currently opened in Cheat Engine.

Start every target-memory workflow with `get_current_process`; call `open_process` only after selecting the intended process.

## Memory

- `read_memory`: Read `bytes`, `int32`, `int64`, `float`, or `string` at an address.
- `write_memory`: Write `bytes`, `int32`, `int64`, `float`, or `string` at an address.

Use symbol/module expressions only when the tool accepts them. When in doubt, call `resolve_address` first and pass a hex address.

## Scanning

- `aob_scan`: Scan for an Array of Bytes pattern such as `AA BB ?? CC DD`.
- `memory_scan`: Perform first or next value scans. Defaults to the main CE GUI scanner and syncs results with the UI.
- `reset_memory_scan`: Reset the main GUI scanner or a named independent scanner.

Useful scan enum values:

- `ScanOption`: `soUnknownValue`, `soExactValue`, `soValueBetween`, `soBiggerThan`, `soSmallerThan`, `soIncreasedValue`, `soIncreasedValueBy`, `soDecreasedValue`, `soDecreasedValueBy`, `soChanged`, `soUnchanged`.
- `VariableType`: `vtByte`, `vtWord`, `vtDword`, `vtQword`, `vtSingle`, `vtDouble`, `vtString`, `vtByteArray`, `vtGrouped`, `vtBinary`, `vtAll`.
- `RoundingType`: `rtRounded`, `rtExtremerounded`, `rtTruncated`.
- `AlignmentType`: `fsmNotAligned`, `fsmAligned`, `fsmLastDigits`.

Typical value scan:

1. `reset_memory_scan`
2. `memory_scan(scanOption="soExactValue", varType="vtDword", input1="100")`
3. Change the value in the target process.
4. `memory_scan(scanOption="soDecreasedValue" | "soIncreasedValue" | "soExactValue", ...)`

For unknown initial value scans, the first call can return `isRegionScan=true`; follow with a narrowing next scan.

## Symbols And Modules

- `enum_modules`: List loaded modules.
- `get_symbol_info`: Resolve and describe a symbol.
- `get_name_from_address`: Convert an address to a symbol or module+offset.
- `get_module_size`: Get a module size by name.
- `enable_symbols`: Enable Windows or kernel symbols.
- `reinitialize_symbols`: Reinitialize CE's symbol handler.
- `wait_for_symbols`: Wait for symbol loading level: `sections`, `exports`, `dotnet`, or `pdb`.
- `get_pointer_size`: Get or set CE pointer size, usually 4 or 8.

Prefer module+offset or symbol names in user-facing explanations; use raw addresses for tool calls that require them.

## Disassembly, Assembly, And Memory View

- `disassemble`: Disassemble at an address or request instruction size.
- `resolve_address`: Resolve strings such as symbols or `module+offset`.
- `disassemble_range`: Disassemble a range of instructions from an address.
- `get_function_range`: Estimate a function range around an address.
- `disassemble_bytes`: Disassemble raw hex bytes.
- `get_previous_opcodes`: Walk backward to previous instruction addresses.
- `enum_memory_regions`: Enumerate memory regions.
- `get_memory_protection`: Read protection flags for an address.
- `set_comment`: Set a CE Memory View comment.
- `assemble`: Assemble one instruction into bytes.
- `auto_assemble`: Execute a Cheat Engine Auto Assembler script.
- `auto_assemble_check`: Syntax-check an Auto Assembler script without executing it.

Always syntax-check Auto Assembler scripts with `auto_assemble_check` before `auto_assemble` when practical.

## Address List

- `get_address_list`: Return current cheat table memory records.
- `add_memory_record`: Add a memory record, including pointer records with comma-separated offsets.
- `update_memory_record`: Update by ID, index, or description.
- `delete_memory_record`: Delete by ID, index, or description.
- `clear_address_list`: Clear all memory records.

For pointer records, offsets are outermost-to-innermost, for example `0x10,0x18`.

## Debugger

- Attach/status: `dbg_start`, `dbg_exit`, `dbg_is_debugging`, `dbg_is_broken`.
- Breakpoints: `dbg_add_bp`, `dbg_toggle_bp`, `dbg_delete_bp`, `dbg_bps`.
- Hit tracking: `dbg_get_bp_hits`, `dbg_clear_bp_hits`.
- Registers: `dbg_gpregs`, `dbg_gpregs_remote`, `dbg_regs`, `dbg_regs_all`, `dbg_regs_named`, `dbg_regs_named_remote`, `dbg_regs_remote`.
- Control flow: `dbg_continue`, `dbg_step_into`, `dbg_step_over`, `dbg_run_to`.
- Stack/memory: `dbg_stacktrace`, `dbg_read`, `dbg_write`.

"Find what writes/accesses" workflow:

1. `dbg_start`
2. `dbg_add_bp(address="0x...", size=4, trigger="write" | "access", trackHits=true)`
3. Trigger the game action.
4. `dbg_get_bp_hits`
5. Inspect instructions and registers, then `dbg_delete_bp`.

## Lua And Conversion

- `execute_lua`: Run CE Lua and return serialized results. Use only when no dedicated MCP tool fits.
- `convert_string`: Convert string formats: `md5`, `ansitoutf8`, or `utf8toansi`.

Read `lua-execution.md` before calling `execute_lua`.
