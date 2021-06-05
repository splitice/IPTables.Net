using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace IPTables.Net.Conntrack
{
    [StructLayout(LayoutKind.Explicit, Pack = 2)]
    public struct ConntrackQueryFilter
    {
        [FieldOffset(0)] public int Key;
        [FieldOffset(4)] public ushort Max;
        [FieldOffset(6)] public ushort CompareLength;
        [FieldOffset(8)] public IntPtr Compare;

        public override string ToString()
        {
            return string.Format("Key: {0}, Max: {1}, CompareLength: {2}, Compare: {3}", Key, Max, CompareLength,
                Compare);
        }
    }
}