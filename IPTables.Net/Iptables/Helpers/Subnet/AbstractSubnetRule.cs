using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.Modules.Core;

namespace IPTables.Net.Iptables.Helpers.Subnet
{
    internal abstract class AbstractSubnetRule: IpTablesRule
    {
        protected AbstractSubnetRule(IpTablesSystem system, IpTablesChain chain, IpTablesChain targetChain, bool isJump) : base(system, chain)
        {
            if (chain.Table != targetChain.Table)
            {
                throw new Exception("Rule chain's table does not match target chain's table");
            }

            var coreModule = GetModuleOrLoad<CoreModule>("core");

            if (isJump)
            {
                coreModule.Jump = targetChain.Name;
            }
            else
            {
                coreModule.Goto = targetChain.Name;
            }
        }
    }
}
