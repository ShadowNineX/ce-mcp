using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using CESDK.Classes;
using ModelContextProtocol.Server;

namespace Tools
{
    /// <summary>
    /// Memory view tools for inspecting memory layout, disassembly, and memory regions.
    /// Provides the AI with a "view" of the target process memory similar to CE's Memory View window.
    /// </summary>
    [McpServerToolType]
    public class MemoryViewTool
    {
        private const string AddressRequired = "Address is required";

        private MemoryViewTool() { }

        [McpServerTool(Name = "disassemble_range"), Description(
            "Disassemble a range of instructions starting at an address. " +
            "Returns parsed instructions with address, bytes, opcode, and comments. " +
            "Use this to view code/instructions at a memory location.")]
        public static object DisassembleRange(
            [Description("Start address as hex string (e.g. '0x401000') or symbol name (e.g. 'game.exe+1000')")] string address,
            [Description("Number of instructions to disassemble (default: 20, max: 200)")] int count = 20)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(address))
                    return new { success = false, error = AddressRequired };

                if (count < 1) count = 1;
                if (count > 200) count = 200;

                // Resolve address - supports symbols
                var resolvedAddr = AddressResolver.GetAddressSafe(address);
                if (!resolvedAddr.HasValue)
                    return new { success = false, error = $"Could not resolve address: {address}" };

                ulong currentAddr = resolvedAddr.Value;
                var instructions = new List<object>();

                for (int i = 0; i < count; i++)
                {
                    var disasm = Disassembler.Disassemble(currentAddr);
                    if (string.IsNullOrEmpty(disasm))
                        break;

                    var parsed = Disassembler.SplitDisassembledString(disasm);
                    var size = Disassembler.GetInstructionSize(currentAddr);
                    var comment = Disassembler.GetComment(currentAddr);

                    instructions.Add(new
                    {
                        address = $"0x{currentAddr:X}",
                        bytes = parsed.Bytes,
                        opcode = parsed.Opcode,
                        extra = parsed.Extra,
                        comment = string.IsNullOrEmpty(comment) ? null : comment,
                        size
                    });

                    currentAddr += (ulong)size;
                }

                var symbolName = AddressResolver.GetNameFromAddress(resolvedAddr.Value);
                return new
                {
                    success = true,
                    startAddress = $"0x{resolvedAddr.Value:X}",
                    symbol = symbolName,
                    instructionCount = instructions.Count,
                    instructions
                };
            }
            catch (Exception ex)
            {
                return new { success = false, error = ex.Message };
            }
        }

        [McpServerTool(Name = "get_function_range"), Description(
            "Get the estimated start and end address of a function containing the given address")]
        public static object GetFunctionRange(
            [Description("Address inside the function as hex string or symbol name")] string address)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(address))
                    return new { success = false, error = AddressRequired };

                var resolvedAddr = AddressResolver.GetAddressSafe(address);
                if (!resolvedAddr.HasValue)
                    return new { success = false, error = $"Could not resolve address: {address}" };

                var (start, end) = Disassembler.GetFunctionRange(resolvedAddr.Value);
                var symbolName = AddressResolver.GetNameFromAddress(start);

                return new
                {
                    success = true,
                    startAddress = $"0x{start:X}",
                    endAddress = $"0x{end:X}",
                    size = end - start,
                    symbol = symbolName
                };
            }
            catch (Exception ex)
            {
                return new { success = false, error = ex.Message };
            }
        }

        [McpServerTool(Name = "disassemble_bytes"), Description("Disassemble raw bytes (hex string) into assembly instructions")]
        public static object DisassembleBytes(
            [Description("Hex byte string to disassemble (e.g. '90 90 CC' or '9090CC')")] string hexBytes,
            [Description("Address to use for relative address calculations")] string? address = null)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(hexBytes))
                    return new { success = false, error = "Hex bytes are required" };

                ulong addr = 0;
                if (!string.IsNullOrEmpty(address))
                {
                    var resolved = AddressResolver.GetAddressSafe(address);
                    if (resolved.HasValue) addr = resolved.Value;
                }

                var result = Disassembler.DisassembleBytes(hexBytes, addr);
                return new { success = true, result };
            }
            catch (Exception ex)
            {
                return new { success = false, error = ex.Message };
            }
        }

        [McpServerTool(Name = "get_previous_opcodes"), Description("Get previous instruction addresses before a given address (useful for navigating backwards in code)")]
        public static object GetPreviousOpcodes(
            [Description("Address to look before, as hex string or symbol name")] string address,
            [Description("Number of previous instructions to find (default: 5, max: 50)")] int count = 5)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(address))
                    return new { success = false, error = AddressRequired };

                if (count < 1) count = 1;
                if (count > 50) count = 50;

                var resolvedAddr = AddressResolver.GetAddressSafe(address);
                if (!resolvedAddr.HasValue)
                    return new { success = false, error = $"Could not resolve address: {address}" };

                // Walk backwards to find previous instructions
                var prevAddresses = new List<ulong>();
                ulong currentAddr = resolvedAddr.Value;
                for (int i = 0; i < count; i++)
                {
                    currentAddr = Disassembler.GetPreviousOpcode(currentAddr);
                    prevAddresses.Add(currentAddr);
                }

                // Now disassemble each one
                var instructions = new List<object>();
                foreach (var addr in prevAddresses.AsEnumerable().Reverse())
                {
                    var disasm = Disassembler.Disassemble(addr);
                    if (!string.IsNullOrEmpty(disasm))
                    {
                        var parsed = Disassembler.SplitDisassembledString(disasm);
                        instructions.Add(new
                        {
                            address = $"0x{addr:X}",
                            bytes = parsed.Bytes,
                            opcode = parsed.Opcode,
                            extra = parsed.Extra
                        });
                    }
                }

                return new { success = true, instructions };
            }
            catch (Exception ex)
            {
                return new { success = false, error = ex.Message };
            }
        }

        [McpServerTool(Name = "enum_memory_regions"), Description(
            "Enumerate all memory regions of the target process. " +
            "Shows memory layout with base address, size, protection, state, and type. " +
            "Useful for understanding process memory layout and finding code/data regions.")]
        public static object EnumMemoryRegions(
            [Description("Filter by state: 'committed' (MEM_COMMIT=0x1000), 'reserved', 'free', or 'all' (default: committed)")] string filter = "committed")
        {
            try
            {
                var regions = MemoryRegions.EnumMemoryRegions();

                var filtered = filter?.ToLower() switch
                {
                    "all" => regions,
                    "reserved" => regions.Where(r => r.State == 0x2000).ToList(),
                    "free" => regions.Where(r => r.State == 0x10000).ToList(),
                    _ => regions.Where(r => r.State == 0x1000).ToList() // committed
                };

                var result = filtered.Select(r => new
                {
                    baseAddress = $"0x{r.BaseAddress:X}",
                    regionSize = r.RegionSize,
                    regionSizeHex = $"0x{r.RegionSize:X}",
                    protect = ProtectToString(r.Protect),
                    state = StateToString(r.State),
                    type = TypeToString(r.Type)
                }).ToList();

                return new { success = true, count = result.Count, regions = result };
            }
            catch (Exception ex)
            {
                return new { success = false, error = ex.Message };
            }
        }

        [McpServerTool(Name = "get_memory_protection"), Description("Get memory protection flags (read/write/execute) for an address")]
        public static object GetMemoryProtection(
            [Description("Memory address as hex string")] string address)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(address))
                    return new { success = false, error = AddressRequired };

                var resolvedAddr = AddressResolver.GetAddressSafe(address);
                if (!resolvedAddr.HasValue)
                    return new { success = false, error = $"Could not resolve address: {address}" };

                var prot = MemoryRegions.GetMemoryProtection(resolvedAddr.Value);
                return new
                {
                    success = true,
                    address = $"0x{resolvedAddr.Value:X}",
                    read = prot.Read,
                    write = prot.Write,
                    execute = prot.Execute
                };
            }
            catch (Exception ex)
            {
                return new { success = false, error = ex.Message };
            }
        }

        [McpServerTool(Name = "set_comment"), Description("Set a comment on a disassembled address (visible in CE Memory View)")]
        public static object SetComment(
            [Description("Memory address as hex string or symbol name")] string address,
            [Description("Comment text to set")] string comment)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(address))
                    return new { success = false, error = AddressRequired };

                var resolvedAddr = AddressResolver.GetAddressSafe(address);
                if (!resolvedAddr.HasValue)
                    return new { success = false, error = $"Could not resolve address: {address}" };

                Disassembler.SetComment(resolvedAddr.Value, comment);
                return new { success = true, address = $"0x{resolvedAddr.Value:X}" };
            }
            catch (Exception ex)
            {
                return new { success = false, error = ex.Message };
            }
        }

        private static string ProtectToString(int protect)
        {
            return protect switch
            {
                0x01 => "NOACCESS",
                0x02 => "READONLY",
                0x04 => "READWRITE",
                0x08 => "WRITECOPY",
                0x10 => "EXECUTE",
                0x20 => "EXECUTE_READ",
                0x40 => "EXECUTE_READWRITE",
                0x80 => "EXECUTE_WRITECOPY",
                _ => $"0x{protect:X}"
            };
        }

        private static string StateToString(int state)
        {
            return state switch
            {
                0x1000 => "MEM_COMMIT",
                0x2000 => "MEM_RESERVE",
                0x10000 => "MEM_FREE",
                _ => $"0x{state:X}"
            };
        }

        private static string TypeToString(int type)
        {
            return type switch
            {
                0x20000 => "MEM_PRIVATE",
                0x40000 => "MEM_MAPPED",
                0x1000000 => "MEM_IMAGE",
                _ => $"0x{type:X}"
            };
        }
    }
}
