using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Netfilter
{
    public interface INetfilterChain
    {
        String Name { get; }

        String Table { get; }

        int IpVersion { get; }
        IEnumerable<INetfilterRule> Rules { get; }

        void AddRule(INetfilterRule rule);
    }

    public interface INetfilterChain<T> : INetfilterChain
    {
        IEnumerable<T> Rules { get; }
    }
}
