using System;
using System.ComponentModel;
using System.Linq;
using CESDK.Classes;
using ModelContextProtocol.Server;

namespace Tools
{
    /// <summary>
    /// Memory read and write tools.
    /// </summary>
    [McpServerToolType]
    public class MemoryTool
    {
        private MemoryTool() { }

        /// <summary>
        /// Checks if a process is currently attached in Cheat Engine.
        /// </summary>
        private static bool IsProcessAttached()
        {
            int pid = Process.GetOpenedProcessID();
            return pid > 0;
        }

        [McpServerTool(Name = "read_memory"), Description("Read memory at the given address with the specified data type")]
        public static object ReadMemory(
            [Description("Memory address as a hex string (e.g. '0x1234ABCD')")] string address,
            [Description("Data type: 'bytes', 'int32', 'int64', 'float', 'string'")] string dataType,
            [Description("Number of bytes to read (required for 'bytes' type)")] int? byteCount = null,
            [Description("Max length for strings (required for 'string' type)")] int? maxLength = null,
            [Description("Whether string is wide char (UTF-16)")] bool wideChar = false)
        {
            if (!IsProcessAttached())
                return new { success = false, error = "No process is attached. Please open a process first using 'open_process' tool." };
            return ToolThread.OnMainThread(() =>
            {
                if (string.IsNullOrWhiteSpace(address))
                    return new { success = false, error = "Address parameter is required" };

                if (string.IsNullOrWhiteSpace(dataType))
                    return new { success = false, error = "DataType parameter is required" };

                if (!TryParseAddress(address, out ulong addr))
                    return new { success = false, error = "Invalid address format" };

                object value = dataType.ToLower() switch
                {
                    "bytes" => byteCount.HasValue && byteCount.Value > 0
                        ? MemoryAccess.ReadBytes(addr, byteCount.Value)
                        : throw new ArgumentException("ByteCount is required for bytes and must be > 0"),

                    "integer" or "int32" or "int" => MemoryAccess.ReadInteger(addr),
                    "qword" or "int64" or "long" => MemoryAccess.ReadQword(addr),
                    "float" => MemoryAccess.ReadFloat(addr),
                    "double" => MemoryAccess.ReadDouble(addr),
                    "byte" => MemoryAccess.ReadByte(addr),
                    "int16" or "short" => MemoryAccess.ReadSmallInteger(addr),

                    "string" => maxLength.HasValue && maxLength.Value > 0
                        ? MemoryAccess.ReadString(addr, maxLength.Value, wideChar)
                        : throw new ArgumentException("MaxLength is required for string and must be > 0"),

                    _ => throw new NotSupportedException($"Unsupported data type: {dataType}")
                };

                return new { success = true, value };
            });
        }

        [McpServerTool(Name = "write_memory"), Description("Write a value to memory at the given address")]
        public static object WriteMemory(
            [Description("Memory address as hex string (e.g. '0x1234ABCD')")] string address,
            [Description("Data type: 'bytes', 'int32', 'int64', 'float', 'string'")] string dataType,
            [Description("Value to write (format depends on dataType)")] string value,
            [Description("Max length for strings")] int? maxLength = null,
            [Description("Whether string is wide char (UTF-16)")] bool wideChar = false)
        {
            if (!IsProcessAttached())
                return new { success = false, error = "No process is attached. Please open a process first using 'open_process' tool." };

            return ToolThread.OnMainThread(() =>
            {
                if (string.IsNullOrWhiteSpace(address))
                    return new { success = false, error = "Address parameter is required" };

                if (string.IsNullOrWhiteSpace(dataType))
                    return new { success = false, error = "DataType parameter is required" };

                if (string.IsNullOrWhiteSpace(value))
                    return new { success = false, error = "Value parameter is required" };

                if (!TryParseAddress(address, out ulong addr))
                    return new { success = false, error = "Invalid address format" };

                object written = dataType.ToLower() switch
                {
                    "bytes" => WriteBytes(addr, value),
                    "integer" or "int32" or "int" => WriteInt32(addr, value),
                    "qword" or "int64" or "long" => WriteInt64(addr, value),
                    "float" => WriteFloat(addr, value),
                    "double" => WriteDouble(addr, value),
                    "byte" => WriteByte(addr, value),
                    "int16" or "short" => WriteInt16(addr, value),
                    "string" => WriteString(addr, value, maxLength, wideChar),
                    _ => throw new NotSupportedException($"Unsupported data type: {dataType}")
                };

                return new { success = true, value = written };
            });
        }

        private static bool TryParseAddress(string address, out ulong result) =>
            ulong.TryParse(address.Replace("0x", "").Replace("0X", ""),
                System.Globalization.NumberStyles.HexNumber, null, out result);

        private static object WriteBytes(ulong address, string value)
        {
            var bytes = value.Split([' ', ','], StringSplitOptions.RemoveEmptyEntries)
                .Select(b => Convert.ToByte(b, 16))
                .ToArray();
            MemoryAccess.WriteBytes(address, bytes);
            return bytes;
        }

        private static object WriteByte(ulong address, string value)
        {
            var b = Convert.ToByte(value);
            MemoryAccess.WriteByte(address, b);
            return b;
        }

        private static object WriteInt16(ulong address, string value)
        {
            if (!short.TryParse(value, out short v))
                throw new ArgumentException("Value must be a valid int16");
            MemoryAccess.WriteSmallInteger(address, v);
            return v;
        }

        private static object WriteInt32(ulong address, string value)
        {
            if (!int.TryParse(value, out int v))
                throw new ArgumentException("Value must be a valid integer");
            MemoryAccess.WriteInteger(address, v);
            return v;
        }

        private static object WriteInt64(ulong address, string value)
        {
            if (!long.TryParse(value, out long v))
                throw new ArgumentException("Value must be a valid long");
            MemoryAccess.WriteQword(address, v);
            return v;
        }

        private static object WriteFloat(ulong address, string value)
        {
            if (!float.TryParse(value, out float v))
                throw new ArgumentException("Value must be a valid float");
            MemoryAccess.WriteFloat(address, v);
            return v;
        }

        private static object WriteDouble(ulong address, string value)
        {
            if (!double.TryParse(value, out double v))
                throw new ArgumentException("Value must be a valid double");
            MemoryAccess.WriteDouble(address, v);
            return v;
        }

        private static object WriteString(ulong address, string value, int? maxLength, bool wideChar)
        {
            string text = value;
            if (maxLength.HasValue && text.Length > maxLength.Value)
                text = text[..maxLength.Value];
            MemoryAccess.WriteString(address, text, wideChar);
            return text;
        }
    }
}
