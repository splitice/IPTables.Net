using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IPTables.Net.Iptables
{
    public enum IpTablesCommandType
    {
        Unknown = 0,
        Add,
        Insert,
        Delete,
        Replace
    }
}
