using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.DataTypes;
using IPTables.Net.Iptables.Modules.Core;
using IPTables.Net.Iptables.Modules.Tcp;
using IPTables.Net.Iptables.Modules.Udp;

namespace IPTables.Net.Iptables.Helpers
{
    public class RulePortHelper
    {
        public static PortOrRange ExtractPort(IpTablesRule rule, bool source)
        {
            var core = rule.GetModule<CoreModule>("core");
            if (core == null || core.Protocol.Null || core.Protocol.Not)
            {
                return new PortOrRange(0);
            }

            var protocol = core.Protocol.Value.ToLower();
            if (protocol == "tcp")
            {
                var pmod = rule.GetModule<TcpModule>("tcp");
                if (pmod == null)
                {
                    return new PortOrRange(0);
                }
                if (source)
                    return pmod.SourcePort.Value;
                return pmod.DestinationPort.Value;
            }
            if (protocol == "udp")
            {
                var pmod = rule.GetModule<UdpModule>("udp");
                if (pmod == null)
                {
                    return new PortOrRange(0);
                }
                if (source)
                    return pmod.SourcePort.Value;
                return pmod.DestinationPort.Value;
            }
            return new PortOrRange(0);
        }
    }
}
