using System;
using System.ComponentModel;
using System.Linq;
using CESDK.Classes;
using ModelContextProtocol.Server;

namespace Tools
{
    /// <summary>
    /// Assembly and auto-assembly tools for code injection and modification.
    /// </summary>
    [McpServerToolType]
    public class AutoAssemblyTool
    {
        private AutoAssemblyTool() { }

        [McpServerTool(Name = "assemble"), Description("Assemble a single instruction into bytes (e.g. 'nop', 'mov eax,ebx', 'jmp 0x12345')")]
        public static object Assemble(
            [Description("Assembly instruction to assemble (e.g. 'nop', 'mov eax,ebx')")] string instruction,
            [Description("Address to assemble at (affects relative addressing). Hex string e.g. '0x401000'")] string? address = null,
            [Description("Preference: 0=none, 1=short, 2=long, 3=far")] int assemblePreference = 0)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(instruction))
                    return new { success = false, error = "Instruction is required" };

                ulong addr = 0;
                if (!string.IsNullOrEmpty(address) && !TryParseAddress(address, out addr))
                    return new { success = false, error = "Invalid address format" };

                var bytes = Assembler.Assemble(instruction, addr, assemblePreference);
                return new
                {
                    success = true,
                    bytes = bytes.Select(b => $"{b:X2}").ToArray(),
                    hex = string.Join(" ", bytes.Select(b => $"{b:X2}")),
                    size = bytes.Length
                };
            }
            catch (Exception ex)
            {
                return new { success = false, error = ex.Message };
            }
        }

        [McpServerTool(Name = "auto_assemble"), Description(
            "Execute a Cheat Engine Auto Assembler script. Supports [ENABLE]/[DISABLE] sections, " +
            "alloc, label, registersymbol, AOB injection, code injection, and all AA features. " +
            "This is the primary way to inject code, create hooks, and modify game code.")]
        public static object AutoAssemble(
            [Description("Auto assembler script text. Supports [ENABLE]/[DISABLE] sections, alloc(), label(), etc.")] string script,
            [Description("If true, assemble into Cheat Engine process instead of target")] bool targetSelf = false)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(script))
                    return new { success = false, error = "Script is required" };

                var result = Assembler.AutoAssemble(script, targetSelf);
                return new { success = result };
            }
            catch (Exception ex)
            {
                return new { success = false, error = ex.Message };
            }
        }

        [McpServerTool(Name = "auto_assemble_check"), Description("Check an Auto Assembler script for syntax errors without executing it")]
        public static object AutoAssembleCheck(
            [Description("Auto assembler script text to check")] string script,
            [Description("Check in enable mode (true) or disable mode (false)")] bool enable = true,
            [Description("If true, check against CE process instead of target")] bool targetSelf = false)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(script))
                    return new { success = false, error = "Script is required" };

                var (syntaxOk, errorMessage) = Assembler.AutoAssembleCheck(script, enable, targetSelf);
                if (syntaxOk)
                    return new { success = true, syntaxValid = true };
                else
                    return new { success = true, syntaxValid = false, error = errorMessage ?? "Unknown syntax error" };
            }
            catch (Exception ex)
            {
                return new { success = false, error = ex.Message };
            }
        }

        private static bool TryParseAddress(string address, out ulong result) =>
            ulong.TryParse(address.Replace("0x", "").Replace("0X", ""),
                System.Globalization.NumberStyles.HexNumber, null, out result);
    }
}
