using System;
using System.ComponentModel;
using System.Linq;
using CESDK.Classes;
using ModelContextProtocol.Server;

namespace Tools
{
    /// <summary>
    /// Process and thread management tools.
    /// </summary>
    [McpServerToolType]
    public class ProcessTool
    {
        private ProcessTool() { }



        [McpServerTool(Name = "get_plugin_version"), Description(
            "Get the ce-mcp plugin version and on-disk path currently loaded in Cheat Engine. " +
            "Use this to verify which build is actually live (CE loads the DLL from disk at startup), " +
            "instead of assuming a freshly-copied file took effect.")]
        public static object GetPluginVersion()
        {
            try
            {
                var asm = System.Reflection.Assembly.GetExecutingAssembly();
                string location = asm.Location;
                string fileVersion = "";
                try
                {
                    if (!string.IsNullOrEmpty(location))
                        fileVersion = System.Diagnostics.FileVersionInfo.GetVersionInfo(location).FileVersion ?? "";
                }
                catch { /* location may be empty for single-file/loaded-from-memory */ }

                return new
                {
                    success = true,
                    version = asm.GetName().Version?.ToString() ?? "unknown",
                    fileVersion,
                    location
                };
            }
            catch (Exception ex)
            {
                return new { success = false, error = ex.Message };
            }
        }

        [McpServerTool(Name = "get_process_list"), Description("Get the list of all running processes")]
        public static object GetProcessList()
        {
            return ToolThread.OnMainThread(() =>
            {
                var processDict = Process.GetProcessList();
                var processes = processDict
                    .Select(kvp => new { processId = kvp.Key, processName = kvp.Value })
                    .OrderBy(p => p.processName)
                    .ToArray();

                return new { success = true, processes };
            });
        }

        [McpServerTool(Name = "open_process"), Description("Open a process by ID or name")]
        public static object OpenProcess(
            [Description("Process ID (integer) or process name to open")] string process)
        {
            return ToolThread.OnMainThread(() =>
            {
                if (string.IsNullOrWhiteSpace(process))
                    return new { success = false, error = "Process parameter is required" };

                var processDict = Process.GetProcessList();

                if (int.TryParse(process, out int pid))
                {
                    if (pid <= 0)
                        return new { success = false, error = "Process ID must be greater than 0" };

                    if (!processDict.ContainsKey(pid))
                        return new { success = false, error = $"Process with ID {pid} not found" };

                    Process.OpenProcess(pid);
                    return new { success = true };
                }

                var target = processDict.FirstOrDefault(p =>
                    string.Equals(p.Value, process, StringComparison.OrdinalIgnoreCase));

                if (target.Key == 0)
                    return new { success = false, error = $"Process with name '{process}' not found" };

                Process.OpenProcess(target.Key);
                return new { success = true };
            });
        }

        [McpServerTool(Name = "get_current_process"), Description("Get information about the process currently opened in Cheat Engine, including process ID, name, and threads")]
        public static object GetCurrentProcess()
        {
            return ToolThread.OnMainThread(() =>
            {
                int processId = Process.GetOpenedProcessID();

                if (processId == 0)
                    return new { success = true, isOpen = false, message = "No process is currently attached" };

                string processName = "Unknown";
                try
                {
                    var processDict = Process.GetProcessList();
                    if (processDict.TryGetValue(processId, out var name))
                        processName = name;
                }
                catch (Exception) { /* process list unavailable, name stays "Unknown" */ }

                var threadList = new ThreadList();
                threadList.Refresh();
                var threads = threadList.GetAllThreadIds();

                return new { success = true, isOpen = true, processId, processName, threads };
            });
        }

    }
}
