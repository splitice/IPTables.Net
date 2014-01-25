using System;
using IPTables.Net.Iptables.Modules.Base;

namespace IPTables.Net.Iptables.Modules
{
    public interface IIptablesModule
    {
        String GetRuleString();
        int Feed(RuleParser parser, bool not);
    }
}