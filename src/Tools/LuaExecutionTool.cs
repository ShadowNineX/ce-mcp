using System;
using System.ComponentModel;
using CESDK.Classes;
using ModelContextProtocol.Server;

namespace Tools
{
    [McpServerToolType]
    public class LuaExecutionTool
    {
        private LuaExecutionTool() { }

        [McpServerTool(Name = "execute_lua"), Description(
            "Execute a Lua script in Cheat Engine's Lua environment and return the result. " +
            "Supports all CE Lua API functions. Returns are automatically serialized including tables. " +
            "Use 'return <value>' to get values back. Multiple return values are supported. " +
            "*** DO NOT USE THIS TOOL if any other available tool can accomplish the task. *** " +
            "Always check for and prefer dedicated tools first: memory_scan, reset_memory_scan, aob_scan, " +
            "open_process, get_current_process, get_process_list, read_memory, write_memory, " +
            "add_memory_record, update_memory_record, delete_memory_record, get_address_list, " +
            "clear_address_list, disassemble, disassemble_bytes, disassemble_range, assemble, " +
            "auto_assemble, auto_assemble_check, enum_modules, enum_memory_regions, get_memory_protection, " +
            "resolve_address, get_name_from_address, get_symbol_info, enable_symbols, aob_scan, etc. " +
            "Only use execute_lua as a last resort when NO other available tool can perform the required action.")]
        public static object ExecuteLua(
            [Description("The Lua code to execute. Use 'return' to get values back.")] string script)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(script))
                    return new { success = false, error = "Script parameter is required" };

                var result = LuaExecutor.Execute(script);

                if (!result.HasValue)
                    return new { success = true, result = (object?)null, message = "Executed successfully (no return value)" };

                if (result.ReturnCount == 1)
                    return new { success = true, result = result.Value };

                return new { success = true, results = result.Values };
            }
            catch (Exception ex)
            {
                return new { success = false, error = ex.Message };
            }
        }
    }
}
