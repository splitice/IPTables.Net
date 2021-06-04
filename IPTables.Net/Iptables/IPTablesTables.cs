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
    internal class IPTablesTables
    {
        static internal Dictionary<String, List<String>> DefaultTables = new Dictionary<string, List<string>>
        {
             { "filter", new List<string>{"INPUT", "FORWARD", "OUTPUT"} },
             { "nat", new List<string>{"PREROUTING", "POSTROUTING", "OUTPUT"} },
             { "raw", new List<string>{"PREROUTING", "OUTPUT"} },
             { "mangle", new List<string>{"INPUT", "FORWARD", "OUTPUT", "PREROUTING", "POSTROUTING"} },
        };

        internal static List<String> GetInternalChains(String table)
        {
            List<String> ret;
            if (!DefaultTables.TryGetValue(table, out ret))
            {
                throw new IpTablesNetException(String.Format("Unknown Table: {0}", table));
            }

            return ret;
        }

        internal static bool IsInternalChain(String table, String chain)
        {
            return GetInternalChains(table).Contains(chain);
        }
    }
}
