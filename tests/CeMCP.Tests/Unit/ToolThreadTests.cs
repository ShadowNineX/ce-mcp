using Tools;

namespace CeMCP.Tests;

[TestClass]
[DoNotParallelize]
public sealed class ToolThreadTests
{
    [TestMethod]
    public void OnMainThread_UsesConfiguredRunner()
    {
        using IDisposable _ = ToolThread.UseMainThreadRunnerForTests(body => body());

        object result = ToolThread.OnMainThread(() => new { success = true, value = 42 });

        ToolResultAssert.IsSuccess(result);
        ToolResultAssert.HasPropertyValue(result, "value", 42);
    }

    [TestMethod]
    public void OnMainThread_NormalizesExceptions()
    {
        using IDisposable _ = ToolThread.UseMainThreadRunnerForTests(_ => throw new InvalidOperationException("boom"));

        object result = ToolThread.OnMainThread(() => new { success = true });

        ToolResultAssert.IsFailure(result, "boom");
    }
}
