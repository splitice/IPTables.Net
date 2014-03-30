using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.DataTypes;
using IPTables.Net.Iptables.Modules.Core;

namespace IPTables.Net.Iptables.Helpers.Subnet.Matches
{
    public class SubnetDestinationAddressMatch : ISubnetMatch
    {
        public void SetRule(IpTablesRule rule, IpCidr cidr)
        {
            rule.GetModuleOrLoad<CoreModule>("core").Destination = new ValueOrNot<IpCidr>(cidr);
        }

        public IpCidr GetRule(IpTablesRule rule)
        {
            var cidr = rule.GetModuleOrLoad<CoreModule>("core").Destination;

            if (cidr.Null)
            {
                throw new Exception("Cidr is NULL");
            }

            if (cidr.Not)
            {
                throw new Exception("NOT is unsupported");
            }

            return cidr.Value;
        }
    }
}
