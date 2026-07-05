using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;

namespace CeMCP.Tests;

internal sealed class LiveMcpClient : IDisposable
{
    public const string ProtocolVersion = "2025-06-18";

    private readonly HttpClient httpClient;
    private int nextId;

    public LiveMcpClient(string serverUrl)
    {
        httpClient = new HttpClient
        {
            BaseAddress = new Uri(serverUrl.EndsWith("/", StringComparison.Ordinal)
                ? serverUrl
                : $"{serverUrl}/"),
            Timeout = TimeSpan.FromSeconds(10)
        };
    }

    public async Task<JsonObject> InitializeAsync()
    {
        JsonObject response = await SendRequestAsync("initialize", new JsonObject
        {
            ["protocolVersion"] = ProtocolVersion,
            ["capabilities"] = new JsonObject(),
            ["clientInfo"] = new JsonObject
            {
                ["name"] = "ce-mcp-live-tests",
                ["version"] = "1.0.0"
            }
        });

        await SendNotificationAsync("notifications/initialized", new JsonObject());
        return response;
    }

    public async Task<JsonArray> ListToolsAsync()
    {
        JsonObject response = await SendRequestAsync("tools/list", new JsonObject());
        return response["result"]?["tools"]?.AsArray()
            ?? throw new InvalidOperationException($"tools/list response did not contain result.tools: {response}");
    }

    public async Task<JsonNode?> CallToolAsync(string name, JsonObject? arguments = null)
    {
        JsonObject response = await SendRequestAsync("tools/call", new JsonObject
        {
            ["name"] = name,
            ["arguments"] = arguments ?? new JsonObject()
        });

        JsonObject result = response["result"]?.AsObject()
            ?? throw new InvalidOperationException($"tools/call response did not contain result: {response}");

        if (result["isError"]?.GetValue<bool>() == true)
            throw new InvalidOperationException($"Tool '{name}' returned an MCP error: {result}");

        return ExtractToolPayload(result);
    }

    public void Dispose() => httpClient.Dispose();

    private async Task<JsonObject> SendRequestAsync(string method, JsonObject parameters)
    {
        int id = Interlocked.Increment(ref nextId);
        JsonObject body = new()
        {
            ["jsonrpc"] = "2.0",
            ["id"] = id,
            ["method"] = method,
            ["params"] = parameters
        };

        JsonObject response = await PostJsonAsync(body);
        if (response["error"] is JsonNode error)
            throw new InvalidOperationException($"MCP request '{method}' failed: {error}");

        return response;
    }

    private async Task SendNotificationAsync(string method, JsonObject parameters)
    {
        JsonObject body = new()
        {
            ["jsonrpc"] = "2.0",
            ["method"] = method,
            ["params"] = parameters
        };

        using HttpRequestMessage request = CreateJsonRequest(body);
        using HttpResponseMessage response = await httpClient.SendAsync(request);
        response.EnsureSuccessStatusCode();
    }

    private async Task<JsonObject> PostJsonAsync(JsonObject body)
    {
        using HttpRequestMessage request = CreateJsonRequest(body);
        using HttpResponseMessage response = await httpClient.SendAsync(request);
        string payload = await response.Content.ReadAsStringAsync();
        response.EnsureSuccessStatusCode();

        string json = response.Content.Headers.ContentType?.MediaType == "text/event-stream"
            ? ExtractJsonFromServerSentEvents(payload)
            : payload;

        return JsonNode.Parse(json)?.AsObject()
            ?? throw new InvalidOperationException($"MCP response was not a JSON object: {payload}");
    }

    private static HttpRequestMessage CreateJsonRequest(JsonObject body)
    {
        HttpRequestMessage request = new(HttpMethod.Post, "")
        {
            Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json")
        };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
        request.Headers.TryAddWithoutValidation("MCP-Protocol-Version", ProtocolVersion);

        return request;
    }

    private static string ExtractJsonFromServerSentEvents(string payload)
    {
        List<string> dataLines = [];

        foreach (string line in payload.Split(["\r\n", "\n"], StringSplitOptions.None))
        {
            if (line.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
            {
                string data = line["data:".Length..].Trim();
                if (data.Length > 0 && data != "[DONE]")
                    dataLines.Add(data);
            }
        }

        if (dataLines.Count == 0)
            throw new InvalidOperationException($"SSE response did not contain JSON data: {payload}");

        return dataLines[^1];
    }

    private static JsonNode? ExtractToolPayload(JsonObject result)
    {
        if (result["structuredContent"] is JsonNode structuredContent)
            return structuredContent;

        if (result["content"] is JsonArray content)
        {
            string? text = content
                .Select(item => item?["text"]?.GetValue<string>())
                .FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));

            if (!string.IsNullOrWhiteSpace(text))
                return JsonNode.Parse(text);
        }

        return result.DeepClone();
    }
}
