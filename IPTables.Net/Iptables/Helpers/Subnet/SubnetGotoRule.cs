using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.Modules.Core;

namespace IPTables.Net.Iptables.Helpers.Subnet
{
    internal class SubnetGotoRule : AbstractSubnetRule, ISubnetTargetRule
    {
        public SubnetGotoRule(NetfilterSystem system, IpTablesChain chain, IpTablesChain targetChain)
            : base(system, chain, targetChain, false)
        {
        }

        public IpTablesChain Target
        {
            get { return _system.GetChain(Table,GetModule<CoreModule>("core").Goto); }
        }
    }
}
