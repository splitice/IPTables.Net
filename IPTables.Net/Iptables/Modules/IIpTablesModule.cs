using System;

namespace IPTables.Net.Iptables.Modules
{
    public interface IIpTablesModule: ICloneable
    {
        bool NeedsLoading { get; }
        String GetRuleString();
        int Feed(RuleParser parser, bool not);
    }
}