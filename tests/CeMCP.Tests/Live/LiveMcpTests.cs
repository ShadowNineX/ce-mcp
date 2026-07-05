using System.Text.Json.Nodes;

namespace CeMCP.Tests;

[TestClass]
[TestCategory("Live")]
[DoNotParallelize]
public sealed class LiveMcpTests
{
    private static string ServerUrl =>
        Environment.GetEnvironmentVariable("CE_MCP_URL") ?? "http://localhost:6300/";

    [TestInitialize]
    public void RequireLiveTestsEnabled()
    {
        if (Environment.GetEnvironmentVariable("CE_MCP_LIVE") != "1")
        {
            Assert.Inconclusive(
                "Live CE MCP tests are opt-in. Load ce-mcp.dll in Cheat Engine, start the MCP server, set CE_MCP_LIVE=1, optionally set CE_MCP_URL, then run dotnet test --filter TestCategory=Live.");
        }
    }

    [TestMethod]
    public async Task LiveServer_InitializesAndListsExpectedTools()
    {
        using LiveMcpClient client = new(ServerUrl);

        JsonObject initialize = await client.InitializeAsync();
        JsonArray tools = await client.ListToolsAsync();
        List<string> toolNames = tools
            .Select(tool => tool?["name"]?.GetValue<string>())
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Select(name => name!)
            .ToList();

        Assert.AreEqual(LiveMcpClient.ProtocolVersion, initialize["result"]?["protocolVersion"]?.GetValue<string>());
        CollectionAssert.Contains(toolNames, "get_plugin_version");
        CollectionAssert.Contains(toolNames, "execute_lua");
        CollectionAssert.Contains(toolNames, "memory_scan");
    }

    [TestMethod]
    public async Task LiveServer_GetPluginVersionReportsLoadedPlugin()
    {
        using LiveMcpClient client = new(ServerUrl);

        await client.InitializeAsync();
        JsonNode? payload = await client.CallToolAsync("get_plugin_version");

        Assert.IsTrue(payload?["success"]?.GetValue<bool>());
        Assert.IsFalse(string.IsNullOrWhiteSpace(payload?["version"]?.GetValue<string>()));
        StringAssert.Contains(payload?["location"]?.GetValue<string>() ?? "", "ce-mcp.dll");
    }

    [TestMethod]
    public async Task LiveServer_ExecuteLuaRunsOnCeMainThread()
    {
        using LiveMcpClient client = new(ServerUrl);

        await client.InitializeAsync();
        JsonNode? payload = await client.CallToolAsync("execute_lua", new JsonObject
        {
            ["script"] = "return { mainThread = inMainThread(), marker = 'ce-mcp-live' }"
        });

        Assert.IsTrue(payload?["success"]?.GetValue<bool>());
        Assert.IsTrue(payload?["result"]?["mainThread"]?.GetValue<bool>());
        Assert.AreEqual("ce-mcp-live", payload?["result"]?["marker"]?.GetValue<string>());
    }

    [TestMethod]
    public async Task LiveServer_GetCurrentProcessIsSafeWithoutTarget()
    {
        using LiveMcpClient client = new(ServerUrl);

        await client.InitializeAsync();
        JsonNode? payload = await client.CallToolAsync("get_current_process");

        Assert.IsTrue(payload?["success"]?.GetValue<bool>());
        Assert.IsNotNull(payload?["isOpen"]);
    }
}
