using System;
using static CESDK.CESDK;

namespace Tools
{
    /// <summary>
    /// Runs tool bodies on Cheat Engine's main GUI thread. CE's Lua state and
    /// engine internals (scanner, found lists, disassembler, symbol handler,
    /// auto-assembler, region enumeration, conversions) are not thread-safe;
    /// executing them directly on the MCP/HTTP worker thread races CE's main
    /// thread and can crash the whole process. Synchronize marshals onto the
    /// main thread — the same mechanism reset_memory_scan and the address-list
    /// tools already use. Exceptions are normalized to the standard
    /// { success = false, error } shape so callers don't each repeat try/catch.
    /// </summary>
    internal static class ToolThread
    {
        public static object OnMainThread(Func<object> body)
        {
            try
            {
                return Synchronize(body);
            }
            catch (Exception ex)
            {
                return new { success = false, error = ex.Message };
            }
        }
    }
}
