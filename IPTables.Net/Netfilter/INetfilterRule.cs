using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Netfilter
{
    public interface INetfilterRule
    {
        void DeleteRule(bool usingPosition = true);
        void AddRule();
        void ReplaceRule(INetfilterRule with);


        void DeleteRule(INetfilterAdapterClient client, bool usingPosition = true);
        void AddRule(INetfilterAdapterClient client);
        void ReplaceRule(INetfilterAdapterClient client, INetfilterRule with);

        int IpVersion { get; }

        PacketCounters Counters { get; }

        INetfilterChain Chain { get; }
    }
}
