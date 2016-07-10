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
        [FieldOffset(0)]
        public Int32 Key;
        [FieldOffset(4)]
        public UInt16 Max;
        [FieldOffset(6)]
        public UInt16 CompareLength;
        [FieldOffset(8)]
        public IntPtr Compare;
    }
}
