using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Iptables.DataTypes
{
    public enum ConnectionState
    {
        Invalid,
        Established,
        New,
        Related,
        Untracked
    }
}
