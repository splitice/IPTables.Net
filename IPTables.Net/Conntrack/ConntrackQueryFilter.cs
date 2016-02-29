using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace IPTables.Net.Conntrack
{
    [StructLayout(LayoutKind.Sequential, Pack=4, Size=16)]
    public struct ConntrackQueryFilter
    {
        public UInt16 Key;
        public UInt16 Max;
        public Int32 CompareLength;
        public IntPtr Compare;
    }
}
