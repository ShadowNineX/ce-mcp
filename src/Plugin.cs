using CEMCP;
using CEMCP.Views;
using CESDK;
using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;


namespace CEMCP
{
    public class McpPlugin : CheatEnginePlugin
    {
        private bool isServerRunning = false;
        private McpServer? mcpServer;
        private Window? configWindow = null;
        private Thread? configThread = null;

        public bool IsServerRunning => isServerRunning;



        public override string Name
        {
            get
            {
                var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "Unknown";
                return $"MCP Server for Cheat Engine v{version}";
            }
        }

        protected override void OnEnable()
        {
            // WPF's InitializeComponent uses Application.LoadComponent which resolves
            // assemblies by name. Since CE loads this DLL via CLR hosting, the default
            // resolver can't find it. Return the already-loaded assembly when asked.
            AppDomain.CurrentDomain.AssemblyResolve += (_, args) =>
            {
                var thisAssembly = Assembly.GetExecutingAssembly();
                var requestedName = new AssemblyName(args.Name);
                return requestedName.Name == thisAssembly.GetName().Name ? thisAssembly : null;
            };

            PluginContext.Lua.RegisterFunction("toggle_mcp_server", ToggleMCPServer);
            PluginContext.Lua.RegisterFunction("update_button_text", UpdateButtonText);
            PluginContext.Lua.RegisterFunction("show_mcp_config", ShowMCPConfig);

            PluginContext.Lua.DoString(@"
                local m=MainForm.Menu
                topm=createMenuItem(m)
                topm.Caption='MCP'
                m.Items.insert(MainForm.miHelp.MenuIndex,topm)

                mcpToggleMenuItem=createMenuItem(m)
                mcpToggleMenuItem.Caption='Start MCP Server'
                mcpToggleMenuItem.OnClick=function(s)
                    toggle_mcp_server()
                end
                topm.add(mcpToggleMenuItem)
                
                mcpConfigMenuItem=createMenuItem(m)
                mcpConfigMenuItem.Caption='Configure'
                mcpConfigMenuItem.OnClick=function(s)
                    show_mcp_config()
                end
                topm.add(mcpConfigMenuItem)
            ");
        }

        protected override void OnDisable()
        {
            StopMCPServer();

            // Remove menu items
            PluginContext.Lua.DoString(@"
                if mcpToggleMenuItem then
                    mcpToggleMenuItem.destroy()
                    mcpToggleMenuItem = nil
                end
                if mcpConfigMenuItem then
                    mcpConfigMenuItem.destroy()
                    mcpConfigMenuItem = nil
                end
                if topm then
                    topm.destroy()
                    topm = nil
                end
            ");
        }

        void ToggleMCPServer()
        {
            if (isServerRunning)
                StopMCPServer();
            else
                StartMCPServer();
        }

        void UpdateButtonText()
        {
            string buttonText = isServerRunning ? "Stop MCP Server" : "Start MCP Server";
            PluginContext.Lua.DoString($"mcpToggleMenuItem.Caption='{buttonText}'");
        }

        void ShowMCPConfig()
        {
            try
            {
                if (configWindow != null && configThread != null && configThread.IsAlive)
                {
                    // Bring existing window to front
                    configWindow.Dispatcher?.BeginInvoke(new Action(() =>
                    {
                        if (configWindow.WindowState == WindowState.Minimized)
                            configWindow.WindowState = WindowState.Normal;
                        configWindow.Activate();
                        configWindow.Topmost = true;
                        configWindow.Topmost = false;
                        configWindow.Focus();
                    }));
                    return;
                }

                // Start window in a new STA thread
                configThread = new Thread(() =>
                {
                    try
                    {
                        // Create Window in code (no XAML)
                        configWindow = new ConfigWindow(this);

                        configWindow.Closed += (sender, e) =>
                        {
                            configWindow = null;
                            System.Windows.Threading.Dispatcher.CurrentDispatcher.BeginInvokeShutdown(
                                System.Windows.Threading.DispatcherPriority.Background);
                        };

                        configWindow.Show();
                        configWindow.Activate();
                        configWindow.Topmost = true;
                        configWindow.Topmost = false;
                        configWindow.Focus();
                        System.Windows.Threading.Dispatcher.Run();
                    }
                    catch (Exception ex)
                    {
                        var msg = $"Error in window thread: {ex.Message}";
                        if (ex.InnerException != null)
                            msg += $" | Inner: {ex.InnerException.Message}";

                        PluginContext.Lua.DoString($"print('Error: {msg.Replace("'", "\\'").Replace("\n", " ").Replace("\r", "")}')");

                        try
                        {
                            var logPath = System.IO.Path.Combine(
                                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                                "CeMCP",
                                "error.log"
                            );
                            System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(logPath)!);
                            System.IO.File.AppendAllText(logPath,
                                $"[{DateTime.Now}] Window Error: {ex.Message}\n" +
                                $"Type: {ex.GetType().Name}\n" +
                                $"Inner: {ex.InnerException?.Message}\n" +
                                $"Stack: {ex.StackTrace}\n\n");
                        }
                        catch
                        {
                            // Best-effort logging - ignore file write failures (e.g., permission issues, disk full)
                            // The error was already logged to CE console via Lua print above
                        }
                        configWindow = null;
                    }
                });

                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    configThread.SetApartmentState(ApartmentState.STA);
                }

                configThread.Start();
            }
            catch (Exception ex)
            {
                PluginContext.Lua.DoString($"print('Error in ShowMCPConfig: {ex.Message}')");
            }
        }

        public void RestartServer()
        {
            if (isServerRunning)
            {
                StopMCPServer();
                StartMCPServer();
            }
        }

        public McpServer? GetServerWrapper()
        {
            return mcpServer;
        }

        public void StartServer()
        {
            StartMCPServer();
        }

        public void StopServer()
        {
            StopMCPServer();
        }

        void StartMCPServer()
        {
            if (isServerRunning) return;

            try
            {
                mcpServer = new McpServer();
                ServerConfig.LoadFromFile();
                ServerConfig.LoadFromEnvironment(); // Environment variables override config file
                mcpServer.Start(ServerConfig.ConfigBaseUrl);

                isServerRunning = true;
                PluginContext.Lua.DoString($"print('MCP Server started on: {ServerConfig.ConfigBaseUrl}')");
                UpdateButtonText();
            }
            catch (Exception ex)
            {
                var errorMsg = $"Failed to start MCP Server: {ex.Message}";
                if (ex.InnerException != null)
                    errorMsg += $"\nInner: {ex.InnerException.Message}";

                PluginContext.Lua.DoString($"print('Error: {errorMsg.Replace("'", "\\'").Replace("\n", " ")}')");

                // Also try to write to a log file for debugging
                try
                {
                    var logPath = System.IO.Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                        "CeMCP",
                        "error.log"
                    );
                    System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(logPath)!);
                    System.IO.File.WriteAllText(logPath,
                        $"[{DateTime.Now}] {errorMsg}\n" +
                        $"Type: {ex.GetType().FullName}\n" +
                        $"Stack: {ex.StackTrace}\n" +
                        (ex.InnerException != null ? $"Inner Stack: {ex.InnerException.StackTrace}\n" : "")
                    );
                }
                catch
                {
                    // Ignore file write errors - logging is best effort only
                }
            }
        }

        void StopMCPServer()
        {
            if (!isServerRunning) return;

            mcpServer?.Stop();
            mcpServer = null;
            isServerRunning = false;
            PluginContext.Lua.DoString("print('MCP SSE Server stopped')");
            UpdateButtonText();
        }
    }
}
