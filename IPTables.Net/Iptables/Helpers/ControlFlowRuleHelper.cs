using System;
using IPTables.Net.Iptables.Modules.Core;
using IPTables.Net.Netfilter;

namespace IPTables.Net.Iptables.Helpers
{
    /// <summary>
    /// Helper methods to create control flow rules (goto/jump).
    /// </summary>
    public static class ControlFlowRuleHelper
    {
        /// <summary>
        /// Create a rule with a jump target to a specified chain
        /// </summary>
        /// <param name="chainIn"></param>
        /// <param name="chainJump"></param>
        /// <param name="system"></param>
        /// <returns></returns>
        public static IpTablesRule CreateJump(IpTablesChain chainIn, String chainJump, NetfilterSystem system)
        {
            var rule = new IpTablesRule(system, chainIn);
            rule.GetModuleOrLoad<CoreModule>("core").Jump = chainJump;
            return rule;
        }

        /// <summary>
        /// Create a rule with a goto target to a specified chain
        /// </summary>
        /// <param name="chainIn"></param>
        /// <param name="chainJump"></param>
        /// <param name="system"></param>
        /// <returns></returns>
        public static IpTablesRule CreateGoto(IpTablesChain chainIn, String chainJump, NetfilterSystem system)
        {
            var rule = new IpTablesRule(system, chainIn);
            rule.GetModuleOrLoad<CoreModule>("core").Goto = chainJump;
            return rule;
        }

        /// <summary>
        /// Create a rule with a jump target to a specified chain
        /// </summary>
        /// <param name="chain"></param>
        /// <param name="target"></param>
        /// <returns></returns>
        public static IpTablesRule CreateJump(IpTablesChain chain, String target)
        {
            return CreateJump(chain, target, chain.System);
        }

        /// <summary>
        /// Create a rule with a goto target to a specified chain
        /// </summary>
        /// <param name="chain"></param>
        /// <param name="target"></param>
        /// <returns></returns>
        public static IpTablesRule CreateGoto(IpTablesChain chain, String target)
        {
            return CreateGoto(chain, target, chain.System);
        }
    }
}