using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Helpers.Subnet.Matches
{
    interface ISubnetMatch
    {
        void SetRule(IpTablesRule rule, IpCidr cidr);

        IpCidr GetRule(IpTablesRule rule);
    }
}
