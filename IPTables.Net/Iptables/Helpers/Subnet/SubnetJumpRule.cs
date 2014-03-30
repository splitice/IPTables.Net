using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.Modules.Core;

namespace IPTables.Net.Iptables.Helpers.Subnet
{
    internal class SubnetJumpRule : AbstractSubnetRule, ISubnetTargetRule
    {
        public SubnetJumpRule(IpTablesSystem system, IpTablesChain chain, IpTablesChain target) : base(system, chain, target, true)
        {
        }

        public IpTablesChain Target
        {
            get { return _system.GetChain(Table, GetModule<CoreModule>("core").Jump); }
        }
    }
}
