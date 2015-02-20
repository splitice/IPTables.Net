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
        static internal Dictionary<String, List<String>> Tables = new Dictionary<string, List<string>>
        {
             { "filter", new List<string>{"INPUT", "FORWARD", "OUTPUT"} },
             { "nat", new List<string>{"PREROUTING", "POSTROUTING", "OUTPUT"} },
             { "raw", new List<string>{"PREROUTING", "POSTROUTING"} },
             { "mangle", new List<string>{"INPUT", "FORWARD", "OUTPUT", "PREROUTING", "POSTROUTING"} },
        };

        internal static List<String> GetInternalChains(String table)
        {
            if (!Tables.ContainsKey(table))
            {
                throw new IpTablesNetException(String.Format("Unknown Table: {0}", table));
            }

            return Tables[table];
        }

        internal static bool IsInternalChain(String table, String chain)
        {
            return GetInternalChains(table).Contains(chain);
        }
    }
}
