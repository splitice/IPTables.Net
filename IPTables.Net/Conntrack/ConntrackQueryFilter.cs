using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Conntrack
{
    public struct ConntrackQueryFilter
    {
        Int32 Key;
        Int32 Max;
        Int32 CompareLength;
        byte[] compare;
    }
}
