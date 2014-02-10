using System;

namespace IPTables.Net.Iptables.Modules
{
    public interface IIptablesModule
    {
        String GetRuleString();
        int Feed(RuleParser parser, bool not);

        bool NeedsLoading { get; }
    }
}