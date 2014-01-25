using System;
using IPTables.Net.Modules.Base;

namespace IPTables.Net.Modules
{
    public interface IIptablesModule
    {
        String GetRuleString();
        int Feed(RuleParser parser, bool not);
    }
}