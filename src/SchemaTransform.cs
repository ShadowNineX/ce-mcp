using System;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Text.Json.Nodes;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.Server;

namespace CEMCP
{
    /// <summary>
    /// Registers MCP tools with a JSON-schema transform that collapses nullable
    /// "type": [ ..., "null" ] arrays down to their single non-null type. The Anthropic
    /// API tool-schema converter (Claude Code and any Anthropic-API MCP client) rejects
    /// array-valued "type" with a 400 error. Optional parameters (int?, string?, bool?)
    /// generate exactly such schemas; since they are already absent from "required",
    /// dropping the redundant "null" is semantically identical.
    /// </summary>
    internal static class SchemaTransform
    {
        public static AIJsonSchemaCreateOptions SchemaCreateOptions { get; } = new()
        {
            TransformSchemaNode = static (context, node) =>
            {
                if (node is JsonObject obj &&
                    obj.TryGetPropertyValue("type", out JsonNode? typeNode) &&
                    typeNode is JsonArray typeArray)
                {
                    string? nonNull = null;
                    bool hadNull = false;
                    int nonNullCount = 0;
                    foreach (JsonNode? member in typeArray)
                    {
                        string? value = member?.GetValue<string>();
                        if (value == "null")
                            hadNull = true;
                        else
                        {
                            nonNullCount++;
                            nonNull ??= value;
                        }
                    }

                    if (hadNull && nonNull is not null && nonNullCount == 1)
                        obj["type"] = nonNull;
                }

                return node;
            }
        };

        public static IMcpServerBuilder WithToolsAndSchemaTransform<[DynamicallyAccessedMembers(
            DynamicallyAccessedMemberTypes.PublicMethods |
            DynamicallyAccessedMemberTypes.NonPublicMethods |
            DynamicallyAccessedMemberTypes.PublicConstructors)] TToolType>(
            this IMcpServerBuilder builder)
        {
            foreach (MethodInfo toolMethod in typeof(TToolType).GetMethods(
                BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance))
            {
                if (toolMethod.GetCustomAttribute<McpServerToolAttribute>() is null)
                    continue;

                MethodInfo method = toolMethod;
                if (method.IsStatic)
                {
                    builder.Services.AddSingleton((Func<IServiceProvider, McpServerTool>)(services =>
                        McpServerTool.Create(method, target: null, new McpServerToolCreateOptions
                        {
                            Services = services,
                            SchemaCreateOptions = SchemaCreateOptions
                        })));
                }
                else
                {
                    builder.Services.AddSingleton((Func<IServiceProvider, McpServerTool>)(services =>
                        McpServerTool.Create(
                            method,
                            r => ActivatorUtilities.CreateInstance(r.Services!, typeof(TToolType)),
                            new McpServerToolCreateOptions
                            {
                                Services = services,
                                SchemaCreateOptions = SchemaCreateOptions
                            })));
                }
            }

            return builder;
        }
    }
}
