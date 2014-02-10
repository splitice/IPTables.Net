using System;

namespace IPTables.Net.Iptables.Modules
{
    public interface IIpTablesModule
    {
        String GetRuleString();

        bool NeedsLoading { get; }
    }
}