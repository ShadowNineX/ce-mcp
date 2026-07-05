using System;
using System.Globalization;

namespace Tools
{
    internal static class AddressParser
    {
        public static bool TryParseHexAddress(string address, out ulong result) =>
            ulong.TryParse(
                address.Replace("0x", "", StringComparison.OrdinalIgnoreCase),
                NumberStyles.HexNumber,
                provider: null,
                out result);
    }
}
