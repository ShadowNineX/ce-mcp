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
        private static readonly string[] OversizedNumericKeywords =
        {
            "default", "const", "minimum", "maximum",
            "exclusiveMinimum", "exclusiveMaximum", "multipleOf",
        };

        public static AIJsonSchemaCreateOptions SchemaCreateOptions { get; } = new()
        {
            TransformSchemaNode = static (context, node) =>
            {
                if (node is not JsonObject obj)
                    return node;

                if (obj.TryGetPropertyValue("type", out JsonNode? typeNode) &&
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

                // Drop numeric schema keywords whose value overflows signed 64-bit.
                // The Anthropic tool-schema converter rejects them with
                // "int too big to convert"; e.g. a `ulong x = ulong.MaxValue`
                // parameter (ScanTool.stopAddress) emits
                // "default": 18446744073709551615. The method still applies its
                // own default at call time, and these are only optional hints/
                // bounds, so removing them is semantically identical.
                foreach (string keyword in OversizedNumericKeywords)
                {
                    if (obj.TryGetPropertyValue(keyword, out JsonNode? valueNode) &&
                        valueNode is JsonValue value && !FitsInt64(value))
                    {
                        obj.Remove(keyword);
                    }
                }

                return node;
            }
        };

        private static bool FitsInt64(JsonValue value)
        {
            // In range as a signed 64-bit integer.
            if (value.TryGetValue(out long _))
                return true;
            // A positive integer larger than long.MaxValue (e.g. ulong.MaxValue).
            if (value.TryGetValue(out ulong _))
                return false;
            // An integral value outside the signed-64 range in either direction.
            if (value.TryGetValue(out decimal dec) && decimal.Truncate(dec) == dec)
                return dec >= long.MinValue && dec <= long.MaxValue;
            // Non-integer (float) or non-numeric — leave it untouched.
            return true;
        }

        /// <summary>
        /// Registers every <see cref="McpServerToolAttribute"/>-marked method on
        /// <typeparamref name="TToolType"/> as an MCP tool, wiring in
        /// <see cref="SchemaCreateOptions"/> so the generated JSON schema is
        /// Anthropic-API compatible.
        /// </summary>
        /// <typeparam name="TToolType">The type whose tool methods are registered.</typeparam>
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
                            r =>
                            {
                                if (r.Services is null)
                                    throw new InvalidOperationException(
                                        $"Cannot create tool '{typeof(TToolType).Name}': the request has no IServiceProvider.");
                                return ActivatorUtilities.CreateInstance(r.Services, typeof(TToolType));
                            },
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
