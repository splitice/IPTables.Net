using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Netfilter;

namespace IPTables.Net.NfTables
{
    public class NfTablesChainSet : NetfilterChainSet<NfTablesChain, NfTablesRule>
    {
        protected override NfTablesChain CreateChain(string tableName, string chainName, NetfilterSystem system)
        {
            return new NfTablesChain(tableName, chainName, system);
        }
    }
}
