using System;
using System.ComponentModel;
using CESDK.Classes;
using ModelContextProtocol.Server;

namespace Tools
{
    [McpServerToolType]
    public class ConversionTool
    {
        private ConversionTool() { }

        [McpServerTool(Name = "convert_string"), Description("Convert string between formats (md5, ansitoutf8, utf8toansi)")]
        public static object ConvertString(
            [Description("The input string to convert")] string input,
            [Description("Conversion type: 'md5', 'ansitoutf8', 'utf8toansi'")] string conversionType)
        {
            return ToolThread.OnMainThread(() =>
            {
                if (string.IsNullOrWhiteSpace(input))
                    return new { success = false, error = "Input is required" };

                if (string.IsNullOrWhiteSpace(conversionType))
                    return new { success = false, error = "Conversion type is required" };

                string result = conversionType.ToLower() switch
                {
                    "md5" => Converter.StringToMD5(input),
                    "ansitoutf8" => Converter.AnsiToUtf8(input),
                    "utf8toansi" => Converter.Utf8ToAnsi(input),
                    _ => throw new NotSupportedException($"Unsupported conversion type: {conversionType}")
                };

                return new { success = true, result };
            });
        }
    }
}
