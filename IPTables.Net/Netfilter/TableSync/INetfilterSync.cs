using System.Collections.Generic;

namespace IPTables.Net.Netfilter.TableSync
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
