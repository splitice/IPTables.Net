using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Exceptions;

namespace IPTables.Net.Iptables
{
    /// <summary>
    /// Data to define the default IPTables tables and chains
    /// </summary>
    public class IPTablesTables
    {
        public static Dictionary<string, List<string>> DefaultTables = new Dictionary<string, List<string>>
        {
            {"filter", new List<string> {"INPUT", "FORWARD", "OUTPUT"}},
            {"nat", new List<string> {"PREROUTING", "POSTROUTING", "INPUT", "OUTPUT"}},
            {"raw", new List<string> {"PREROUTING", "OUTPUT"}},
            {"mangle", new List<string> {"INPUT", "FORWARD", "OUTPUT", "PREROUTING", "POSTROUTING"}}
        };

        internal static List<string> GetInternalChains(string table)
        {
            List<string> ret;
            if (!DefaultTables.TryGetValue(table, out ret))
                throw new IpTablesNetException(string.Format("Unknown Table: {0}", table));

            return ret;
        }

        internal static bool IsInternalChain(string table, string chain)
        {
            return GetInternalChains(table).Contains(chain);
        }
    }
}