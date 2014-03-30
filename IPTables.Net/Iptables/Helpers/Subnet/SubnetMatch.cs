using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.Helpers.Subnet.Matches;

namespace IPTables.Net.Iptables.Helpers.Subnet
{
    public class SubnetMatch
    {
        public static SubnetDestinationAddressMatch DestinationAddress = new SubnetDestinationAddressMatch();
        public static SubnetSourceAddressMatch SourceAddress = new SubnetSourceAddressMatch();
    }
}
