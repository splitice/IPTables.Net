using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Conntrack
{
    public struct ConntrackQueryFilter
    {
        public Int32 Key;
        public Int32 Max;
        public Int32 CompareLength;
        public byte[] Compare;
    }
}
