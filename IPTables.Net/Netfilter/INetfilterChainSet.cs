using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Netfilter
{
    public interface INetfilterChainSet
    {
        IEnumerable<INetfilterChain> Chains { get; }
        INetfilterChain GetChainOrDefault(string chain, string table);
    }
}
