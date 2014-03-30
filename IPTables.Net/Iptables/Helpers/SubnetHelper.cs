using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.DataTypes;
using IPTables.Net.Iptables.Helpers.Subnet;
using IPTables.Net.Iptables.Helpers.Subnet.Matches;
using IPTables.Net.Supporting;

namespace IPTables.Net.Iptables.Helpers
{
    class SubnetHelper
    {
        internal static ISubnetTargetRule CreateJump(IpTablesChain chain, IpTablesChain chainTarget)
        {
            return new SubnetJumpRule(chain.System, chain, chainTarget);
        }

        private class CidrComparer: IComparer<IpCidr>
        {
            public int Compare(IpCidr x, IpCidr y)
            {
                if (x.Address.ToInt() == y.Address.ToInt())
                    return 0;

                return (x.Address.ToInt() > y.Address.ToInt()) ? -1 : 1;
            }
        }

        internal static void CreateJumps(IpTablesChain chainToCreateIn, IEnumerable<IpTablesRule> rules, ISubnetMatch subnetMatch, bool needsContainer = true)
        {
            SortedDictionary<IpCidr, List<IpTablesRule>> cidrs = new SortedDictionary<IpCidr, List<IpTablesRule>>();
            foreach (var rule in rules)
            {
                var cidr = subnetMatch.GetRule(rule);
                if (!cidrs.ContainsKey(cidr))
                {
                    cidrs.Add(cidr, new List<IpTablesRule>());
                }

                cidrs[cidr].Add(rule);
            }
        }
    }
}
