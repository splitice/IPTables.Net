using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Iptables.IpSet.Sync
{
    public interface IIPSetSync
    {
        void SyncChainRules(IEnumerable<IpSetEntry> with, IEnumerable<IpSetEntry> currentRules);
    }
}
