using System.Text.Json;
using System.Text.Json.Nodes;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace CeMCP.Tests;

internal sealed class LiveMcpClient : IAsyncDisposable
{
    public const string ProtocolVersion = "2025-06-18";

    private readonly McpClient client;

    private LiveMcpClient(McpClient client)
    {
        this.client = client;
    }

    public string NegotiatedProtocolVersion =>
        client.NegotiatedProtocolVersion
        ?? throw new InvalidOperationException("The MCP client did not report a negotiated protocol version.");

    public static async Task<LiveMcpClient> ConnectAsync(string serverUrl)
    {
        HttpClientTransport transport = new(new HttpClientTransportOptions
        {
            Endpoint = NormalizeEndpoint(serverUrl),
            Name = "ce-mcp-live-tests",
            TransportMode = HttpTransportMode.StreamableHttp,
            ConnectionTimeout = TimeSpan.FromSeconds(10)
        });

        try
        {
            McpClient client = await McpClient.CreateAsync(transport, new McpClientOptions
            {
                ClientInfo = new Implementation
                {
                    Name = "ce-mcp-live-tests",
                    Version = "1.0.0"
                },
                Capabilities = new ClientCapabilities(),
                ProtocolVersion = ProtocolVersion
            });

            return new LiveMcpClient(client);
        }
        catch
        {
            await transport.DisposeAsync();
            throw;
        }
    }

    public ValueTask<IList<McpClientTool>> ListToolsAsync() => client.ListToolsAsync();

    public async Task<JsonNode?> CallToolAsync(
        string name,
        IReadOnlyDictionary<string, object?>? arguments = null)
    {
        CallToolResult result = await client.CallToolAsync(
            name,
            arguments ?? new Dictionary<string, object?>());

        if (result.IsError == true)
            throw new InvalidOperationException($"Tool '{name}' returned an MCP error: {FormatContent(result)}");

        return ExtractToolPayload(result);
    }

    public ValueTask DisposeAsync() => client.DisposeAsync();

    private static Uri NormalizeEndpoint(string serverUrl)
    {
        string endpoint = serverUrl.EndsWith("/", StringComparison.Ordinal)
            ? serverUrl
            : $"{serverUrl}/";

        return new Uri(endpoint, UriKind.Absolute);
    }

    private static JsonNode? ExtractToolPayload(CallToolResult result)
    {
        if (result.StructuredContent is JsonElement structuredContent)
            return JsonNode.Parse(structuredContent.GetRawText());

        string? text = result.Content
            .OfType<TextContentBlock>()
            .Select(block => block.Text)
            .FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));

        return string.IsNullOrWhiteSpace(text)
            ? JsonSerializer.SerializeToNode(result)
            : ParseTextPayload(text);
    }

    private static JsonNode? ParseTextPayload(string text)
    {
        try
        {
            return JsonNode.Parse(text);
        }
        catch (JsonException)
        {
            return JsonValue.Create(text);
        }
    }

    private static string FormatContent(CallToolResult result)
    {
        string text = string.Join(Environment.NewLine, result.Content
            .OfType<TextContentBlock>()
            .Select(block => block.Text)
            .Where(value => !string.IsNullOrWhiteSpace(value)));

        return string.IsNullOrWhiteSpace(text)
            ? JsonSerializer.Serialize(result)
            : text;
    }
}
