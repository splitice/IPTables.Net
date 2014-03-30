using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Netfilter.Sync
{
    public interface INetfilterSync
    {
        void SyncChainRules(IEnumerable<INetfilterRule> with, IEnumerable<INetfilterRule> currentRules);
    }

    public interface INetfilterSync<T>: INetfilterSync
    {
        void SyncChainRules(IEnumerable<T> with, IEnumerable<T> currentRules);
    }
}
