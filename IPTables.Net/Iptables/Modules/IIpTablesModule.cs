using System;

namespace IPTables.Net.Iptables.Modules
{
    public interface IIpTablesModule
    {
        bool NeedsLoading { get; }
        String GetRuleString();
    }
}