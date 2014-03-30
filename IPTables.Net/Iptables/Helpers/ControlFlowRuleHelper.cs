using System;
using IPTables.Net.Iptables.Modules.Core;

namespace IPTables.Net.Iptables.Helpers
{
    public static class ControlFlowRuleHelper
    {
        public static IpTablesRule CreateJump(IpTablesChain chainIn, String chainJump, NetfilterSystem system)
        {
            var rule = new IpTablesRule(system, chainIn);
            rule.GetModuleOrLoad<CoreModule>("core").Jump = chainJump;
            return rule;
        }

        public static IpTablesRule CreateGoto(IpTablesChain chainIn, String chainJump, NetfilterSystem system)
        {
            var rule = new IpTablesRule(system, chainIn);
            rule.GetModuleOrLoad<CoreModule>("core").Goto = chainJump;
            return rule;
        }

        public static IpTablesRule CreateJump(IpTablesChain chain, String target)
        {
            return CreateJump(chain, target, chain.System);
        }

        public static IpTablesRule CreateGoto(IpTablesChain chain, String target)
        {
            return CreateGoto(chain, target, chain.System);
        }
    }
}