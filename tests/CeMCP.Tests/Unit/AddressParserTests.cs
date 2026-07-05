using Tools;

namespace CeMCP.Tests;

[TestClass]
public sealed class AddressParserTests
{
    [TestMethod]
    [DataRow("401000", 0x401000UL)]
    [DataRow("0x401000", 0x401000UL)]
    [DataRow("0X401000", 0x401000UL)]
    [DataRow("FFFFFFFFFFFFFFFF", ulong.MaxValue)]
    public void TryParseHexAddress_AcceptsHexAddresses(string text, ulong expected)
    {
        bool parsed = AddressParser.TryParseHexAddress(text, out ulong actual);

        Assert.IsTrue(parsed);
        Assert.AreEqual(expected, actual);
    }

    [TestMethod]
    [DataRow("")]
    [DataRow("not-hex")]
    [DataRow("-1")]
    public void TryParseHexAddress_RejectsInvalidAddresses(string text)
    {
        bool parsed = AddressParser.TryParseHexAddress(text, out _);

        Assert.IsFalse(parsed);
    }
}
