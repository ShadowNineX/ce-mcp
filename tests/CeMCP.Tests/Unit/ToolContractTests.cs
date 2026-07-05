using System.ComponentModel;
using System.Reflection;
using ModelContextProtocol.Server;

namespace CeMCP.Tests;

[TestClass]
public sealed class ToolContractTests
{
    [TestMethod]
    public void ToolNamesAreUniqueAndExplicit()
    {
        IReadOnlyList<ToolMethod> methods = GetToolMethods();
        List<string> duplicateNames = methods
            .GroupBy(method => method.Name, StringComparer.Ordinal)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key)
            .ToList();

        Assert.IsFalse(
            duplicateNames.Count > 0,
            $"Duplicate MCP tool names: {string.Join(", ", duplicateNames)}");
    }

    [TestMethod]
    public void ToolMethodsHaveDescriptions()
    {
        foreach (ToolMethod method in GetToolMethods())
        {
            Assert.IsFalse(string.IsNullOrWhiteSpace(method.Name), $"{method.Method} has no explicit tool name.");
            Assert.IsNotNull(
                method.Method.GetCustomAttribute<System.ComponentModel.DescriptionAttribute>(),
                $"{method.Method.DeclaringType?.FullName}.{method.Method.Name} is missing DescriptionAttribute.");
        }
    }

    [TestMethod]
    public void ToolTypesKeepExpectedShape()
    {
        foreach (Type type in GetToolTypes())
        {
            Assert.IsTrue(type.IsPublic, $"{type.FullName} should be public.");
            Assert.IsFalse(type.IsAbstract && type.IsSealed, $"{type.FullName} should not be a static class.");

            ConstructorInfo[] constructors = type.GetConstructors(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            Assert.IsTrue(
                constructors.Any(constructor => constructor.IsPrivate && constructor.GetParameters().Length == 0),
                $"{type.FullName} should keep a private parameterless constructor.");
        }
    }

    internal static IReadOnlyList<string> GetToolNames() =>
        GetToolMethods().Select(method => method.Name).Order(StringComparer.Ordinal).ToArray();

    private static IReadOnlyList<ToolMethod> GetToolMethods() =>
        GetToolTypes()
            .SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance))
            .Select(method => new { Method = method, Attribute = method.GetCustomAttribute<McpServerToolAttribute>() })
            .Where(method => method.Attribute is not null)
            .Select(method => new ToolMethod(method.Method, method.Attribute?.Name ?? string.Empty))
            .ToArray();

    private static IReadOnlyList<Type> GetToolTypes() =>
        typeof(Tools.ProcessTool).Assembly
            .GetTypes()
            .Where(type => type.GetCustomAttribute<McpServerToolTypeAttribute>() is not null)
            .OrderBy(type => type.FullName, StringComparer.Ordinal)
            .ToArray();

    private sealed record ToolMethod(MethodInfo Method, string Name);
}
