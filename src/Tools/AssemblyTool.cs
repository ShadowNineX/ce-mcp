using System;
using System.ComponentModel;
using CESDK.Classes;
using ModelContextProtocol.Server;

namespace Tools
{
    /// <summary>
    /// Disassembly and address resolution tools.
    /// </summary>
    [McpServerToolType]
    public class AssemblyTool
    {
        private AssemblyTool() { }

        [McpServerTool(Name = "disassemble"), Description("Disassemble instructions or get instruction size at a memory address")]
        public static object Disassemble(
            [Description("Memory address as hex string (e.g. '0x1234ABCD')")] string address,
            [Description("Request type: 'disassemble' or 'get-instruction-size' (default: disassemble)")] string? requestType = null)
        {
            return ToolThread.OnMainThread(() =>
            {
                if (string.IsNullOrWhiteSpace(address))
                    return new { success = false, error = "Address parameter is required" };

                if (!TryParseAddress(address, out ulong addr))
                    return new { success = false, error = "Invalid address format" };

                string result = requestType?.ToLower() switch
                {
                    "get-instruction-size" => Disassembler.GetInstructionSize(addr).ToString(),
                    "disassemble" or null or "" => Disassembler.Disassemble(addr)?.ToString() ?? "Failed to disassemble",
                    _ => throw new NotSupportedException($"Unsupported request type: {requestType}")
                };

                return new { success = true, result };
            });
        }

        [McpServerTool(Name = "resolve_address"), Description("Resolve an address from a string expression (supports symbols, module+offset, etc.)")]
        public static object ResolveAddress(
            [Description("Address string expression to resolve")] string addressString,
            [Description("Whether to resolve as local address")] bool local = false)
        {
            return ToolThread.OnMainThread(() =>
            {
                if (string.IsNullOrWhiteSpace(addressString))
                    return new { success = false, error = "Address string is required" };

                var address = AddressResolver.GetAddressSafe(addressString, local);
                return new { success = true, address = address.HasValue ? $"0x{address.Value:X}" : "0" };
            });
        }

        private static bool TryParseAddress(string address, out ulong result) =>
            ulong.TryParse(address.Replace("0x", "").Replace("0X", ""),
                System.Globalization.NumberStyles.HexNumber, null, out result);
    }
}
