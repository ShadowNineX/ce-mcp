using System;
using System.Collections.Generic;
using System.ComponentModel;
using CESDK.Classes;
using ModelContextProtocol.Server;
using static CESDK.CESDK;

namespace Tools
{
    [McpServerToolType]
    public class AddressListTool
    {
        private AddressListTool() { }

        [McpServerTool(Name = "get_address_list"), Description("Get all memory records in the cheat table")]
        public static object GetAddressList()
        {
            try
            {
                var records = Synchronize(() =>
                {
                    var al = new AddressList();
                    var result = new List<object>();
                    for (int i = 0; i < al.Count; i++)
                    {
                        var r = al.GetMemoryRecord(i);
                        result.Add(new
                        {
                            id = r.ID,
                            index = r.Index,
                            description = r.Description,
                            address = r.Address,
                            value = r.Value,
                            active = r.Active
                        });
                    }
                    return result;
                });

                return new { success = true, count = records.Count, records };
            }
            catch (Exception ex)
            {
                return new { success = false, error = ex.Message };
            }
        }

        [McpServerTool(Name = "add_memory_record"), Description("Add a new memory record to the cheat table. Supports pointer records: set offsets to a comma-separated list of hex/decimal offsets in outermost-to-innermost order (e.g. '0x10,0x18' means dereference base, add 0x10, dereference, add 0x18 to get final address). Leave offsets empty for a plain address record.")]
        public static object AddMemoryRecord(
            [Description("Description for the memory record")] string description = "New Entry",
            [Description("Memory address or pointer base (e.g. '0x1234ABCD' or '\"Tutorial-x86_64.exe\"+1A2B3C')")] string address = "0",
            [Description("Variable type (e.g. vtDword, vtFloat, etc.)")] VariableType varType = VariableType.vtDword,
            [Description("Initial value")] string value = "0",
            [Description("Comma-separated pointer offsets in outermost-to-innermost order, hex or decimal (e.g. '0x10,0x18,0x0,0x18' means: deref base+0x10, deref+0x18, deref+0x0, deref+0x18 = final address). Omit for a plain address.")] string offsets = "",
            [Description("Freeze/activate the record immediately after adding")] bool active = false)
        {
            try
            {
                var offsetList = new List<long>();
                if (!string.IsNullOrWhiteSpace(offsets))
                {
                    foreach (var part in offsets.Split(','))
                    {
                        var trimmed = part.Trim();
                        offsetList.Add(trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                            ? Convert.ToInt64(trimmed, 16)
                            : long.Parse(trimmed));
                    }
                }

                var record = Synchronize(() =>
                {
                    var al = new AddressList();
                    var r = al.CreateMemoryRecord();
                    r.Description = description;
                    r.Address = address;
                    r.VarType = varType;
                    if (offsetList.Count > 0)
                    {
                        // CE stores offsets innermost-first: index 0 = final offset (closest to value)
                        offsetList.Reverse();
                        r.OffsetCount = offsetList.Count;
                        for (int i = 0; i < offsetList.Count; i++)
                            r.SetOffset(i, offsetList[i]);
                    }
                    r.Value = value;
                    if (active)
                        r.Active = true;
                    return new
                    {
                        id = r.ID,
                        description = r.Description,
                        address = r.Address,
                        offsetCount = r.OffsetCount,
                        value = r.Value,
                        active = r.Active
                    };
                });

                return new { success = true, record };
            }
            catch (Exception ex)
            {
                return new { success = false, error = ex.Message };
            }
        }

#pragma warning disable S107 // Methods should not have too many parameters
#pragma warning disable S3776 // Cognitive Complexity
        [McpServerTool(Name = "update_memory_record"), Description("Update a memory record (find by id, index, or description). Supports updating pointer offsets via newOffsets.")]
        public static object UpdateMemoryRecord(
            [Description("Record ID to find")] int? id = null,
            [Description("Record index to find")] int? index = null,
            [Description("Record description to find")] string? description = null,
            [Description("New description")] string? newDescription = null,
            [Description("New address")] string? newAddress = null,
            [Description("New variable type")] VariableType? newVarType = null,
            [Description("New value")] string? newValue = null,
            [Description("Set active state")] bool? active = null,
            [Description("New comma-separated pointer offsets in hex or decimal (e.g. '0x7E8'). Set to empty string to clear offsets.")] string? newOffsets = null)
        {
            try
            {
                var result = Synchronize(() =>
                {
                    var al = new AddressList();
                    var r = FindRecord(al, id, index, description);
                    if (r == null)
                        return (object?)null;

                    if (!string.IsNullOrEmpty(newDescription))
                        r.Description = newDescription;
                    if (!string.IsNullOrEmpty(newAddress))
                        r.Address = newAddress;
                    if (newVarType.HasValue)
                        r.VarType = newVarType.Value;
                    if (newOffsets != null)
                    {
                        if (string.IsNullOrWhiteSpace(newOffsets))
                        {
                            r.OffsetCount = 0;
                        }
                        else
                        {
                            var offsetList = new List<long>();
                            foreach (var part in newOffsets.Split(','))
                            {
                                var trimmed = part.Trim();
                                offsetList.Add(trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                                    ? Convert.ToInt64(trimmed, 16)
                                    : long.Parse(trimmed));
                            }
                            // CE stores offsets innermost-first: index 0 = final offset (closest to value)
                            offsetList.Reverse();
                            r.OffsetCount = offsetList.Count;
                            for (int i = 0; i < offsetList.Count; i++)
                                r.SetOffset(i, offsetList[i]);
                        }
                    }
                    if (!string.IsNullOrEmpty(newValue))
                        r.Value = newValue;
                    if (active.HasValue)
                        r.Active = active.Value;

                    return new
                    {
                        id = r.ID,
                        description = r.Description,
                        address = r.Address,
                        offsetCount = r.OffsetCount,
                        value = r.Value,
                        active = r.Active
                    };
                });

                if (result == null)
                    return new { success = false, error = "Record not found" };

                return new { success = true, record = result };
            }
            catch (Exception ex)
            {
                return new { success = false, error = ex.Message };
            }
        }
#pragma warning restore S107
#pragma warning restore S3776

        [McpServerTool(Name = "delete_memory_record"), Description("Delete a memory record (find by id, index, or description)")]
        public static object DeleteMemoryRecord(
            [Description("Record ID to find")] int? id = null,
            [Description("Record index to find")] int? index = null,
            [Description("Record description to find")] string? description = null)
        {
            try
            {
                var found = Synchronize(() =>
                {
                    var al = new AddressList();
                    var r = FindRecord(al, id, index, description);
                    if (r == null)
                        return false;

                    al.DeleteMemoryRecord(r);
                    return true;
                });

                if (!found)
                    return new { success = false, error = "Record not found" };

                return new { success = true };
            }
            catch (Exception ex)
            {
                return new { success = false, error = ex.Message };
            }
        }

        [McpServerTool(Name = "clear_address_list"), Description("Clear all memory records from the cheat table")]
        public static object ClearAddressList()
        {
            try
            {
                Synchronize(() =>
                {
                    var al = new AddressList();
                    al.Clear();
                });
                return new { success = true };
            }
            catch (Exception ex)
            {
                return new { success = false, error = ex.Message };
            }
        }

        private static MemoryRecord? FindRecord(AddressList al, int? id, int? index, string? description)
        {
            if (id.HasValue)
                return al.GetMemoryRecordByID(id.Value);
            if (index.HasValue)
                return al.GetMemoryRecord(index.Value);
            if (!string.IsNullOrEmpty(description))
                return al.GetMemoryRecordByDescription(description);

            throw new ArgumentException("Provide id, index, or description to find the record");
        }
    }
}
