using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using CESDK.Classes;
using ModelContextProtocol.Server;

namespace Tools
{
    /// <summary>
    /// Symbol management tools for modules, symbols, and address resolution.
    /// </summary>
    [McpServerToolType]
    public class SymbolTool
    {
        private SymbolTool() { }

        [McpServerTool(Name = "enum_modules"), Description(
            "List all loaded modules (DLLs/EXEs) in the target process with their base addresses, sizes, and paths")]
        public static object EnumModules()
        {
            try
            {
                var modules = SymbolManager.EnumModules();
                var result = modules.Select(m => new
                {
                    name = m.Name,
                    address = $"0x{m.Address:X}",
                    size = m.Size,
                    sizeHex = $"0x{m.Size:X}",
                    is64Bit = m.Is64Bit,
                    path = m.PathToFile
                }).ToList();

                return new { success = true, count = result.Count, modules = result };
            }
            catch (Exception ex)
            {
                return new { success = false, error = ex.Message };
            }
        }

        [McpServerTool(Name = "get_symbol_info"), Description("Get detailed information about a symbol (function, variable, export)")]
        public static object GetSymbolInfo(
            [Description("Symbol name to look up (e.g. 'kernel32.CreateFileW', 'game.exe+1000')")] string symbolName)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(symbolName))
                    return new { success = false, error = "Symbol name is required" };

                var info = SymbolManager.GetSymbolInfo(symbolName);
                if (info == null)
                    return new { success = false, error = $"Symbol not found: {symbolName}" };

                return new
                {
                    success = true,
                    moduleName = info.ModuleName,
                    searchKey = info.SearchKey,
                    address = $"0x{info.Address:X}",
                    size = info.Size
                };
            }
            catch (Exception ex)
            {
                return new { success = false, error = ex.Message };
            }
        }

        [McpServerTool(Name = "get_name_from_address"), Description("Get the symbol name or module+offset for a given address")]
        public static object GetNameFromAddress(
            [Description("Address as hex string (e.g. '0x7FF612340000')")] string address,
            [Description("Include module names in result")] bool moduleNames = true,
            [Description("Include symbol names in result")] bool symbols = true,
            [Description("Include section names in result")] bool sections = false)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(address))
                    return new { success = false, error = "Address is required" };

                if (!TryParseAddress(address, out ulong addr))
                    return new { success = false, error = "Invalid address format" };

                var name = AddressResolver.GetNameFromAddress(addr, moduleNames, symbols, sections);
                var inModule = AddressResolver.InModule(addr);
                var inSystemModule = AddressResolver.InSystemModule(addr);

                return new
                {
                    success = true,
                    address = $"0x{addr:X}",
                    name,
                    inModule,
                    inSystemModule
                };
            }
            catch (Exception ex)
            {
                return new { success = false, error = ex.Message };
            }
        }

        [McpServerTool(Name = "get_module_size"), Description("Get the size of a loaded module by name")]
        public static object GetModuleSize(
            [Description("Module name (e.g. 'game.exe', 'kernel32.dll')")] string moduleName)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(moduleName))
                    return new { success = false, error = "Module name is required" };

                var size = SymbolManager.GetModuleSize(moduleName);
                var baseAddr = AddressResolver.GetAddressSafe(moduleName);

                return new
                {
                    success = true,
                    module = moduleName,
                    baseAddress = baseAddr.HasValue ? $"0x{baseAddr.Value:X}" : null,
                    size,
                    sizeHex = $"0x{size:X}"
                };
            }
            catch (Exception ex)
            {
                return new { success = false, error = ex.Message };
            }
        }

        [McpServerTool(Name = "enable_symbols"), Description(
            "Enable additional symbol loading. 'windows' downloads Windows PDB files (slow first time). " +
            "'kernel' enables kernel mode symbols.")]
        public static object EnableSymbols(
            [Description("Symbol type to enable: 'windows' or 'kernel'")] string symbolType)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(symbolType))
                    return new { success = false, error = "Symbol type is required ('windows' or 'kernel')" };

                switch (symbolType.ToLower())
                {
                    case "windows":
                        SymbolManager.EnableWindowsSymbols();
                        return new { success = true, message = "Windows symbols enabled (PDB download may still be in progress)" };
                    case "kernel":
                        SymbolManager.EnableKernelSymbols();
                        return new { success = true, message = "Kernel symbols enabled" };
                    default:
                        return new { success = false, error = $"Unknown symbol type: {symbolType}. Use 'windows' or 'kernel'" };
                }
            }
            catch (Exception ex)
            {
                return new { success = false, error = ex.Message };
            }
        }

        [McpServerTool(Name = "reinitialize_symbols"), Description("Reinitialize the symbol handler (useful after new modules are loaded)")]
        public static object ReinitializeSymbols(
            [Description("Wait until symbol reinitialization is complete")] bool waitTillDone = true)
        {
            try
            {
                SymbolManager.ReinitializeSymbolHandler(waitTillDone);
                var done = SymbolManager.SymbolsDoneLoading();
                return new { success = true, symbolsLoaded = done };
            }
            catch (Exception ex)
            {
                return new { success = false, error = ex.Message };
            }
        }

        [McpServerTool(Name = "wait_for_symbols"), Description("Wait for symbols to finish loading at a specific level")]
        public static object WaitForSymbols(
            [Description("Symbol level to wait for: 'sections', 'exports', 'dotnet', or 'pdb'")] string level = "exports")
        {
            try
            {
                var symbolLevel = level?.ToLower() switch
                {
                    "sections" => SymbolLevel.Sections,
                    "exports" => SymbolLevel.Exports,
                    "dotnet" => SymbolLevel.DotNet,
                    "pdb" => SymbolLevel.PDB,
                    _ => throw new ArgumentException($"Unknown symbol level: {level}. Use 'sections', 'exports', 'dotnet', or 'pdb'")
                };

                SymbolWaiter.WaitFor(symbolLevel);
                return new { success = true, level = level, loaded = true };
            }
            catch (Exception ex)
            {
                return new { success = false, error = ex.Message };
            }
        }

        [McpServerTool(Name = "get_pointer_size"), Description("Get or set the pointer size CE uses (in bytes). Some 64-bit processes only use 32-bit addresses.")]
        public static object GetOrSetPointerSize(
            [Description("If provided, set the pointer size to this value (4 or 8 bytes). If omitted, returns current size.")] int? newSize = null)
        {
            try
            {
                if (newSize.HasValue)
                {
                    SymbolManager.SetPointerSize(newSize.Value);
                    return new { success = true, pointerSize = newSize.Value };
                }
                else
                {
                    var size = SymbolManager.GetPointerSize();
                    return new { success = true, pointerSize = size };
                }
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
