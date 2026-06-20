using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using CESDK.Classes;
using ModelContextProtocol.Server;
using static CESDK.CESDK;

namespace Tools
{
    /// <summary>
    /// Memory scanning tools: AOB pattern scanning and value scanning.
    /// Supports scanning via the main CE GUI scanner (synced with UI) or independent scanners.
    /// </summary>
    [McpServerToolType]
    public class ScanTool
    {
        private ScanTool() { }

        /// <summary>
        /// Independent scanners keyed by user-chosen name. The main UI scanner is not stored here.
        /// </summary>
        private static readonly Dictionary<string, MemScan> independentScanners = new();

        /// <summary>
        /// Checks if a process is currently attached in Cheat Engine.
        /// </summary>
        private static bool IsProcessAttached()
        {
            int pid = Process.GetOpenedProcessID();
            return pid > 0;
        }

        /// <summary>
        /// Gets the main CE UI scanner (synced with the GUI).
        /// </summary>
        private static MemScan GetMainScanner()
        {
            return MemScan.GetCurrentMemScan();
        }

        /// <summary>
        /// Gets or creates an independent scanner by name.
        /// </summary>
        private static MemScan GetOrCreateIndependentScanner(string name)
        {
            if (!independentScanners.TryGetValue(name, out var scanner))
            {
                scanner = new MemScan();
                independentScanners[name] = scanner;
            }
            return scanner;
        }

        [McpServerTool(Name = "aob_scan"), Description("Scan memory for an Array of Bytes pattern")]
        public static object AobScan(
            [Description("AOB pattern string (e.g. 'AA BB ?? CC DD')")] string pattern,
            [Description("Memory protection flags filter")] string? protectionFlags = null,
            [Description("Alignment type (0=none)")] int? alignmentType = null,
            [Description("Alignment parameter")] string? alignmentParam = null)
        {
            if (!IsProcessAttached())
                return new { success = false, error = "No process is attached. Please open a process first using 'open_process' tool." };

            try
            {
                if (string.IsNullOrWhiteSpace(pattern))
                    return new { success = false, error = "AOB pattern is required" };

                var result = AobScanner.Scan(
                    pattern,
                    protectionFlags,
                    alignmentType ?? 0,
                    alignmentParam
                );

                var addresses = result.Select(addr => $"0x{addr:X}").ToList();
                return new { success = true, addresses };
            }
            catch (Exception ex)
            {
                return new { success = false, error = ex.Message };
            }
        }

#pragma warning disable S107 // Methods should not have too many parameters
        [McpServerTool(Name = "memory_scan"), Description(
            "Perform a memory scan for values in the opened process. " +
            "By default uses the main CE GUI scanner which syncs results with the Cheat Engine UI. " +
            "Automatically detects first scan vs next scan. Use reset_memory_scan to start fresh.")]
        public static object MemoryScan(
            [Description("Scan option (e.g. soExactValue, soValueBetween, etc.)")] ScanOption scanOption = ScanOption.soExactValue,
            [Description("Variable type (e.g. vtDword, vtFloat, vtString, etc.)")] VariableType varType = VariableType.vtDword,
            [Description("Primary scan input value")] string input1 = "",
            [Description("Secondary scan input (for between scans)")] string? input2 = null,
            [Description("Start address for scan range")] ulong startAddress = 0,
            [Description("Stop address for scan range")] ulong stopAddress = ulong.MaxValue,
            [Description("Memory protection flags (e.g. '+W-C')")] string protectionFlags = "+W-C",
            [Description("Alignment type")] AlignmentType alignmentType = AlignmentType.fsmAligned,
            [Description("Alignment parameter")] string alignmentParam = "4",
            [Description("Whether input is hexadecimal")] bool isHexadecimalInput = false,
            [Description("Whether to scan for unicode strings")] bool isUnicodeScan = false,
            [Description("Whether string scan is case sensitive")] bool isCaseSensitive = false,
            [Description("Whether to use percentage-based scanning")] bool isPercentageScan = false,
            [Description("Optional scanner name. If omitted, uses the main CE GUI scanner (synced with UI). " +
                         "Provide a name to use an independent scanner that won't affect the CE GUI.")] string? scannerName = null)
        {
            if (!IsProcessAttached())
                return new { success = false, error = "No process is attached. Please open a process first using 'open_process' tool." };

            try
            {
                bool isMainScanner = string.IsNullOrEmpty(scannerName);

                // Run all scanner work on CE's main GUI thread. The scan engine
                // and found list are not thread-safe; running Scan/InitializeResults
                // over a large result set on the MCP worker thread races CE's main
                // thread and crashes the process (notably nextScan over big found
                // lists). Synchronize marshals onto the main thread, matching
                // reset_memory_scan.
                return Synchronize<object>(() =>
                {
                    MemScan scanner = isMainScanner ? GetMainScanner() : GetOrCreateIndependentScanner(scannerName!);

                    var parameters = new ScanParameters
                    {
                        ScanOption = scanOption,
                        VarType = varType,
                        Input1 = input1,
                        Input2 = input2 ?? string.Empty,
                        StartAddress = startAddress,
                        StopAddress = stopAddress,
                        ProtectionFlags = protectionFlags,
                        AlignmentType = alignmentType,
                        AlignmentParam = alignmentParam,
                        IsHexadecimalInput = isHexadecimalInput,
                        IsUnicodeScan = isUnicodeScan,
                        IsCaseSensitive = isCaseSensitive,
                        IsPercentageScan = isPercentageScan
                    };

                    // Use the high-level Scan() method which auto-detects first vs next scan
                    scanner.Scan(parameters);
                    scanner.WaitTillDone();

                    // Check if this was a region scan (unknown initial value)
                    // Region scans mark memory regions but don't have individual addressable results
                    bool isRegionScan = scanner.LastScanWasRegionScan;

                    if (isRegionScan)
                    {
                        // For region scans, we can't read individual addresses (could be billions of bytes)
                        // Just report success - the next scan will narrow it down
                        return new
                        {
                            success = true,
                            isRegionScan = true,
                            message = "Region scan completed. Memory regions marked for next scan. Perform a next scan with a specific condition (e.g., decreased value, exact value) to narrow down results.",
                            syncedWithUI = isMainScanner
                        };
                    }

                    // Initialize results using the high-level API
                    scanner.InitializeResults();

                    int count = scanner.GetResultCount();
                    if (count == 0)
                        return new { success = true, count = 0, results = Array.Empty<object>(), syncedWithUI = isMainScanner };

                    var maxResults = Math.Min(count, 1000);
                    var results = new object[maxResults];

                    for (int i = 0; i < maxResults; i++)
                    {
                        string addrStr = scanner.GetResultAddress(i);
                        if (!ulong.TryParse(addrStr.Replace("0x", ""), System.Globalization.NumberStyles.HexNumber, null, out ulong address))
                            throw new FormatException($"Invalid address format from scan result: {addrStr}");

                        object value = scanner.GetResultValue(i);
                        results[i] = new { address = $"0x{address:X}", value };
                    }

                    return new { success = true, count, results, syncedWithUI = isMainScanner };
                });
            }
            catch (Exception ex)
            {
                return new { success = false, error = ex.Message };
            }
        }
#pragma warning restore S107

        [McpServerTool(Name = "reset_memory_scan"), Description(
            "Reset the memory scan state to start a fresh scan. " +
            "If no scannerName is provided, resets the main CE GUI scanner. " +
            "Provide a scannerName to reset a specific independent scanner.")]
        public static object ResetMemoryScan(
            [Description("Optional scanner name. If omitted, resets the main CE GUI scanner.")] string? scannerName = null)
        {
            try
            {
                if (string.IsNullOrEmpty(scannerName))
                {
                    // Reset the main CE GUI scanner
                    // Synchronize to ensure UI updates properly on CE's main thread
                    Synchronize(() =>
                    {
                        var scanner = GetMainScanner();
                        // First deinitialize the foundlist to clear the UI panel and results
                        scanner.DeinitializeFoundList();
                        // Then call newScan to reset the scan state and clear results
                        scanner.NewScan();
                        // Do NOT reinitialize - let CE manage the UI state naturally

                        // Clear the UI counter label
                        LuaExecutor.Execute(@"
                            local mainForm = getMainForm()
                            if mainForm then
                                local foundLabel = mainForm.findComponentByName('foundcountlabel')
                                if foundLabel then
                                    foundLabel.Caption = '0'
                                end
                            end
                        ");
                    });
                }
                else
                {
                    // Remove and recreate the independent scanner
                    independentScanners.Remove(scannerName);
                }

                return new { success = true };
            }
            catch (Exception ex)
            {
                return new { success = false, error = ex.Message };
            }
        }
    }
}
