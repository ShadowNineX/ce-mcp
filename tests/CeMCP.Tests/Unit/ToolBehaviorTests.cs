using Tools;

namespace CeMCP.Tests;

[TestClass]
[DoNotParallelize]
public sealed class ToolBehaviorTests
{
    [TestInitialize]
    public void UseInlineMainThreadRunner()
    {
        mainThreadRunner = ToolThread.UseMainThreadRunnerForTests(body => body());
    }

    [TestCleanup]
    public void RestoreMainThreadRunner()
    {
        mainThreadRunner?.Dispose();
    }

    private IDisposable? mainThreadRunner;

    [TestMethod]
    public void ProcessTool_GetPluginVersion_ReturnsLoadedAssemblyMetadata()
    {
        object result = ProcessTool.GetPluginVersion();

        ToolResultAssert.IsSuccess(result);
        StringAssert.Contains(ToolResultAssert.GetProperty<string>(result, "location"), "ce-mcp.dll");
    }

    [TestMethod]
    public void ConversionTool_ValidatesRequiredInput()
    {
        object result = ConversionTool.ConvertString("", "md5");

        ToolResultAssert.IsFailure(result, "Input is required");
    }

    [TestMethod]
    public void ConversionTool_ValidatesRequiredConversionType()
    {
        object result = ConversionTool.ConvertString("abc", "");

        ToolResultAssert.IsFailure(result, "Conversion type is required");
    }

    [TestMethod]
    public void ConversionTool_NormalizesUnsupportedConversionType()
    {
        object result = ConversionTool.ConvertString("abc", "sha9000");

        ToolResultAssert.IsFailure(result, "Unsupported conversion type: sha9000");
    }

    [TestMethod]
    public void AssemblyTool_Disassemble_ValidatesAddress()
    {
        object result = AssemblyTool.Disassemble("");

        ToolResultAssert.IsFailure(result, "Address parameter is required");
    }

    [TestMethod]
    public void AssemblyTool_Disassemble_RejectsInvalidAddress()
    {
        object result = AssemblyTool.Disassemble("not-hex");

        ToolResultAssert.IsFailure(result, "Invalid address format");
    }

    [TestMethod]
    public void AssemblyTool_Disassemble_NormalizesUnsupportedRequestType()
    {
        object result = AssemblyTool.Disassemble("0x401000", "decode-magic");

        ToolResultAssert.IsFailure(result, "Unsupported request type: decode-magic");
    }

    [TestMethod]
    public void AutoAssemblyTool_Assemble_ValidatesInstruction()
    {
        object result = AutoAssemblyTool.Assemble("");

        ToolResultAssert.IsFailure(result, "Instruction is required");
    }

    [TestMethod]
    public void AutoAssemblyTool_Assemble_RejectsInvalidAddressBeforeCeCall()
    {
        object result = AutoAssemblyTool.Assemble("nop", "not-hex");

        ToolResultAssert.IsFailure(result, "Invalid address format");
    }

    [TestMethod]
    public void AutoAssemblyTool_AutoAssemble_ValidatesScript()
    {
        object result = AutoAssemblyTool.AutoAssemble("");

        ToolResultAssert.IsFailure(result, "Script is required");
    }

    [TestMethod]
    public void AutoAssemblyTool_AutoAssembleCheck_ValidatesScript()
    {
        object result = AutoAssemblyTool.AutoAssembleCheck("");

        ToolResultAssert.IsFailure(result, "Script is required");
    }

    [TestMethod]
    public void MemoryViewTool_DisassembleRange_ValidatesAddress()
    {
        object result = MemoryViewTool.DisassembleRange("");

        ToolResultAssert.IsFailure(result, "Address is required");
    }

    [TestMethod]
    public void MemoryViewTool_GetFunctionRange_ValidatesAddress()
    {
        object result = MemoryViewTool.GetFunctionRange("");

        ToolResultAssert.IsFailure(result, "Address is required");
    }

    [TestMethod]
    public void MemoryViewTool_DisassembleBytes_ValidatesBytes()
    {
        object result = MemoryViewTool.DisassembleBytes("");

        ToolResultAssert.IsFailure(result, "Hex bytes are required");
    }

    [TestMethod]
    public void MemoryViewTool_GetPreviousOpcodes_ValidatesAddress()
    {
        object result = MemoryViewTool.GetPreviousOpcodes("");

        ToolResultAssert.IsFailure(result, "Address is required");
    }

    [TestMethod]
    public void MemoryViewTool_GetMemoryProtection_ValidatesAddress()
    {
        object result = MemoryViewTool.GetMemoryProtection("");

        ToolResultAssert.IsFailure(result, "Address is required");
    }

    [TestMethod]
    public void MemoryViewTool_SetComment_ValidatesAddress()
    {
        object result = MemoryViewTool.SetComment("", "note");

        ToolResultAssert.IsFailure(result, "Address is required");
    }
}
