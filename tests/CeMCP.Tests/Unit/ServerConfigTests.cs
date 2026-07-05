using CEMCP;

namespace CeMCP.Tests;

[TestClass]
[DoNotParallelize]
public sealed class ServerConfigTests
{
    [TestInitialize]
    public void Reset()
    {
        Environment.SetEnvironmentVariable("MCP_HOST", null);
        Environment.SetEnvironmentVariable("MCP_PORT", null);
        ServerConfig.ConfigHost = "127.0.0.1";
        ServerConfig.ConfigPort = 6300;
        ServerConfig.ConfigServerName = "Cheat Engine MCP Server";
    }

    [TestCleanup]
    public void Cleanup() => Reset();

    [TestMethod]
    public void ConfigBaseUrl_UsesConfiguredHostAndPort()
    {
        ServerConfig.ConfigHost = "0.0.0.0";
        ServerConfig.ConfigPort = 7777;

        Assert.AreEqual("http://0.0.0.0:7777", ServerConfig.ConfigBaseUrl);
    }

    [TestMethod]
    public void LoadFromEnvironment_OverridesHostAndValidPort()
    {
        Environment.SetEnvironmentVariable("MCP_HOST", "localhost");
        Environment.SetEnvironmentVariable("MCP_PORT", "6400");

        ServerConfig.LoadFromEnvironment();

        Assert.AreEqual("localhost", ServerConfig.ConfigHost);
        Assert.AreEqual(6400, ServerConfig.ConfigPort);
    }

    [TestMethod]
    public void LoadFromEnvironment_IgnoresInvalidPort()
    {
        ServerConfig.ConfigPort = 6300;
        Environment.SetEnvironmentVariable("MCP_PORT", "not-a-port");

        ServerConfig.LoadFromEnvironment();

        Assert.AreEqual(6300, ServerConfig.ConfigPort);
    }
}
