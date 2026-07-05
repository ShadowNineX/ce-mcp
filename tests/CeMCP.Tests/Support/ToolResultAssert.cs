namespace CeMCP.Tests;

internal static class ToolResultAssert
{
    public static void IsSuccess(object result)
    {
        Assert.IsTrue(GetProperty<bool>(result, "success"));
    }

    public static void IsFailure(object result, string expectedError)
    {
        Assert.IsFalse(GetProperty<bool>(result, "success"));
        Assert.AreEqual(expectedError, GetProperty<string>(result, "error"));
    }

    public static void HasPropertyValue<T>(object result, string propertyName, T expected)
    {
        Assert.AreEqual(expected, GetProperty<T>(result, propertyName));
    }

    public static T GetProperty<T>(object result, string propertyName)
    {
        object? value = result.GetType().GetProperty(propertyName)?.GetValue(result);
        Assert.IsInstanceOfType<T>(value, $"Property '{propertyName}' had unexpected type.");
        return (T)value;
    }
}
