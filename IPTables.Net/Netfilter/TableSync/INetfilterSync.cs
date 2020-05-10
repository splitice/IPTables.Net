using System.Collections.Generic;

namespace IPTables.Net.Netfilter.TableSync
{
    public interface INetfilterSync<T>
    {
        void SyncChainRules(INetfilterAdapterClient client, IEnumerable<T> with, INetfilterChain<T> currentChain);
    }
}
