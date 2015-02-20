using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Netfilter
{
    public interface INetfilterChainSet
    {
        INetfilterChain GetChainOrDefault(string chain, string table);

        IEnumerable<INetfilterChain> Chains { get; }
    }
}
