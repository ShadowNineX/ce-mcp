using CESDK.Classes;
using Tools;

namespace CeMCP.Tests;

[TestClass]
public sealed class LuaExecutionToolTests
{
    [TestMethod]
    public void ExecuteLua_ReturnsFailureForBlankScriptWithoutTouchingCe()
    {
        object result = LuaExecutionTool.ExecuteLua("");

        ToolResultAssert.IsFailure(result, "Script parameter is required");
    }

    [TestMethod]
    public void ExecuteLuaCore_ReturnsNoValueShape()
    {
        object result = LuaExecutionTool.ExecuteLuaCore("print('ok')", _ => new LuaResult { ReturnCount = 0 });

        ToolResultAssert.IsSuccess(result);
        Assert.IsNull(result.GetType().GetProperty("result")?.GetValue(result));
        ToolResultAssert.HasPropertyValue(result, "message", "Executed successfully (no return value)");
    }

    [TestMethod]
    public void ExecuteLuaCore_ReturnsSingleValueShape()
    {
        object result = LuaExecutionTool.ExecuteLuaCore("return 123", _ => new LuaResult
        {
            ReturnCount = 1,
            Value = 123
        });

        ToolResultAssert.IsSuccess(result);
        ToolResultAssert.HasPropertyValue(result, "result", 123);
    }

    [TestMethod]
    public void ExecuteLuaCore_ReturnsMultipleValueShape()
    {
        var values = new List<object?> { "a", 2, true };

        object result = LuaExecutionTool.ExecuteLuaCore("return 'a', 2, true", _ => new LuaResult
        {
            ReturnCount = values.Count,
            Values = values
        });

        ToolResultAssert.IsSuccess(result);
        CollectionAssert.AreEqual(values, ToolResultAssert.GetProperty<List<object?>>(result, "results"));
    }

    [TestMethod]
    public void ExecuteLuaCore_NormalizesLuaExceptions()
    {
        object result = LuaExecutionTool.ExecuteLuaCore("return nope", _ => throw new LuaExecutorException("bad lua"));

        ToolResultAssert.IsFailure(result, "bad lua");
    }
}
