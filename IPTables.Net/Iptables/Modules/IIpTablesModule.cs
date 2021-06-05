using System;

namespace IPTables.Net.Iptables.Modules
{
    public interface IIpTablesModule : ICloneable
    {
        bool NeedsLoading { get; }
        string GetRuleString();
        int Feed(CommandParser parser, bool not);
    }
}