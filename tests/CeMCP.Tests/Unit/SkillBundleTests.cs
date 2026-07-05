namespace CeMCP.Tests;

[TestClass]
public sealed class SkillBundleTests
{
    [TestMethod]
    public void ProjectCopiesSkillBesideDllWithoutLocalMachineState()
    {
        string projectFile = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "CeMCP.csproj"));

        StringAssert.Contains(projectFile, "<Content Include=\"skills\\ce-mcp\\**\\*.*\"");
        StringAssert.Contains(projectFile, "<CopyToOutputDirectory>PreserveNewest</CopyToOutputDirectory>");
        StringAssert.Contains(projectFile, "<TargetPath>skills\\ce-mcp\\%(RecursiveDir)%(Filename)%(Extension)</TargetPath>");
        StringAssert.Contains(projectFile, "skills\\ce-mcp\\references\\local-cheat-engine.md");
        Assert.IsFalse(
            projectFile.Contains("<EmbeddedResource Include=\"skills", StringComparison.OrdinalIgnoreCase),
            "The distributable skill must be copied beside the DLL, not embedded into it.");
    }

    [TestMethod]
    public void SkillCatalogListsEveryExposedTool()
    {
        string root = FindRepositoryRoot();
        string catalog = File.ReadAllText(Path.Combine(root, "skills", "ce-mcp", "references", "tool-catalog.md"));

        foreach (string toolName in ToolContractTests.GetToolNames())
            StringAssert.Contains(catalog, $"`{toolName}`");
    }

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);

        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "CeMCP.sln")))
                return directory.FullName;

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not find repository root from test output directory.");
    }
}
