using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Conntrack
{
    public struct ConntrackQueryFilter
    {
        public UInt16 Key;
        public UInt16 Max;
        public Int32 CompareLength;
        public byte[] Compare;
    }
}
