using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Iptables.DataTypes
{
    [Flags]
    public enum HashLimitMode
    {
        Upto = 0,
        Packets = 0,
        Above = 1,
        Bytes = 2
    }
}