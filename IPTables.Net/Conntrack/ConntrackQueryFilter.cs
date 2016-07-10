using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace IPTables.Net.Conntrack
{
    [StructLayout(LayoutKind.Explicit)]
    public struct ConntrackQueryFilter
    {
        [FieldOffset(0)]
        public Int32 Key;
        [FieldOffset(4)]
        public Int32 Max;
        [FieldOffset(8)]
        public Int32 CompareLength;
        [FieldOffset(12)]
        public IntPtr Compare;
    }
}
