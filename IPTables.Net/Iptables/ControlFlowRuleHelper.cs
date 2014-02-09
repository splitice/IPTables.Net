using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using SystemInteract;
using IPTables.Net.Iptables.Modules.Core;

namespace IPTables.Net.Iptables
{
    public static class ControlFlowRuleHelper
    {
        static IpTablesRule CreateJump(String chain, ISystemFactory system)
        {
            IpTablesRule rule = new IpTablesRule(system);
            rule.GetModuleOrLoad<CoreModule>("core").Jump = chain;
            return rule;
        }

        static IpTablesRule CreateGoto(String chain, ISystemFactory system)
        {
            IpTablesRule rule = new IpTablesRule(system);
            rule.GetModuleOrLoad<CoreModule>("core").Goto = chain;
            return rule;
        }
    }
}
