using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace CEMCP
{
    public class McpServer
    {
        private WebApplication? _app;
        private CancellationTokenSource? _cts;

        public void Start(string baseUrl)
        {
            if (_app != null) return; // Already running

            var builder = WebApplication.CreateBuilder(new WebApplicationOptions
            {
                Args = [],
                ContentRootPath = System.IO.Path.GetTempPath(),
                WebRootPath = System.IO.Path.GetTempPath()
            });

            // Setup MCP server with Streamable HTTP transport and all tools
            builder.Services.AddMcpServer(options =>
            {
                options.ServerInfo = new()
                {
                    Name = ServerConfig.ConfigServerName,
                    Version = System.Reflection.Assembly.GetExecutingAssembly()
                        .GetName().Version?.ToString() ?? "1.0.0"
                };
            })
            .WithHttpTransport(options =>
            {
                options.Stateless = true;
            })
            .WithTools<Tools.ProcessTool>()
            .WithTools<Tools.LuaExecutionTool>()
            .WithTools<Tools.MemoryTool>()
            .WithTools<Tools.ScanTool>()
            .WithTools<Tools.AssemblyTool>()
            .WithTools<Tools.ConversionTool>()
            .WithTools<Tools.AddressListTool>()
            .WithTools<Tools.AutoAssemblyTool>()
            .WithTools<Tools.MemoryViewTool>()
            .WithTools<Tools.SymbolTool>();

            builder.Logging.ClearProviders(); // Disable logging
            builder.WebHost.UseUrls(baseUrl);

            // Build app
            _app = builder.Build();

            // Map MCP endpoints (Streamable HTTP)
            _app.MapMcp();

            // Start server in background
            _cts = new CancellationTokenSource();
            Task.Run(async () => await _app.RunAsync());
        }

        public void Stop()
        {
            if (_app == null) return; // Not running

            var appToStop = _app;
            var ctsToStop = _cts;
            _app = null;
            _cts = null;

            // Stop server in background (don't freeze CE)
            Task.Run(async () =>
            {
                try
                {
                    ctsToStop?.Cancel();
                    await appToStop.StopAsync();
                    await appToStop.DisposeAsync();
                    ctsToStop?.Dispose();
                }
                catch
                {
                    // Best-effort cleanup
                }
            });
        }

        public bool IsRunning => _app != null;
    }
}
