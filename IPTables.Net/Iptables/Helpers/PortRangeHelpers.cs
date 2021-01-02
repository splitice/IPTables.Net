using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.DataTypes;
using IPTables.Net.Iptables.IpSet;
using IPTables.Net.Iptables.Modules.Core;
using IPTables.Net.Iptables.Modules.IpSet;
using IPTables.Net.Iptables.Modules.Multiport;
using IPTables.Net.Iptables.Modules.Tcp;
using IPTables.Net.Iptables.Modules.Udp;

namespace IPTables.Net.Iptables.Helpers
{
    public class PortRangeHelpers
    {
        public static List<PortOrRange> CompressRanges(List<PortOrRange> ranges)
        {
            List<PortOrRange> ret = new List<PortOrRange>();
            PortOrRange start = new PortOrRange(0);
            int previous = -1, previousLower = -1;
            foreach (PortOrRange current in ranges.OrderBy((a)=>a.LowerPort))
            {
                if (current.LowerPort == (previous + 1))
                {
                    if (start.LowerPort == 0)
                    {
                        start = new PortOrRange((uint)previousLower, current.UpperPort);
                    }
                }
                else
                {
                    if (start.UpperPort != 0)
                    {
                        ret.Add(new PortOrRange(start.LowerPort, (uint)previous));
                        start = new PortOrRange(0);
                    }
                    else if (previous != -1)
                    {
                        ret.Add(new PortOrRange((uint)previousLower,(uint)previous));
                    }
                }
                previous = (int)current.UpperPort;
                previousLower = (int) current.LowerPort;
            }
            if (start.UpperPort != 0)
            {
                ret.Add(new PortOrRange(start.LowerPort, (uint)previous));
                // ReSharper disable RedundantAssignment
                start = new PortOrRange(0);
                // ReSharper restore RedundantAssignment
            }
            else if (previous != -1)
            {
                ret.Add(new PortOrRange((uint)previousLower,(uint)previous));
            }
            return ret;
        }

        public static int CountRequiredMultiports(List<PortOrRange> ports)
        {
            SortRangeFirstLowHigh(ports);

            int count = 0, ruleCount = ports.Count == 0 ? 0 : 1;
            for (var i = 0; i < ports.Count; i++)
            {
                if (count == 14 && ports[i].IsRange())
                {
                    ruleCount++;
                    count = 0;
                }
                if (count == 15)
                {
                    ruleCount++;
                    count = 0;
                }

                var e = ports[i];
                if (e.IsRange())
                {
                    count += 2;
                }
                else
                {
                    count++;
                }
            }
            return ruleCount;
        }

        public static void SortRangeFirstLowHigh(List<PortOrRange> ports)
        {
            ports.Sort((a, b) =>
            {
                if (a.IsRange() && b.IsRange() || !a.IsRange() && !b.IsRange())
                {
                    if (a.LowerPort < b.LowerPort)
                    {
                        return -1;
                    }
                    return 1;
                }
                if (a.IsRange()) return -1;
                return 1;
            });
        }



        public static void DestinationPortSetter(IpTablesRule rule, List<PortOrRange> ranges)
        {
            var protocol = rule.GetModule<CoreModule>("core").Protocol;
            if (ranges.Count == 1 && !protocol.Null && !protocol.Not)
            {
                if (protocol.Value == "tcp")
                {
                    var tcp = rule.GetModuleOrLoad<TcpModule>("tcp");
                    tcp.DestinationPort = new ValueOrNot<PortOrRange>(ranges[0]);
                }
                else
                {
                    var tcp = rule.GetModuleOrLoad<UdpModule>("udp");
                    tcp.DestinationPort = new ValueOrNot<PortOrRange>(ranges[0]);
                }
            }
            else
            {
                var multiport = rule.GetModuleOrLoad<MultiportModule>("multiport");
                multiport.DestinationPorts = new ValueOrNot<IEnumerable<PortOrRange>>(ranges);
            }
        }

        public static void DestinationPortIpSetter(IpTablesRule rule, List<PortOrRange> ranges, string setName, IpSetSets sets)
        {
            IpTablesSystem system = rule.Chain.System as IpTablesSystem;
            IpSetSet set;
            if (!sets.HasSet(setName))
            {
                set = new IpSetSet(IpSetType.Bitmap | IpSetType.Port, setName, 0, PosixFamilyHelpers.GetIpFamily(rule.IpVersion), system, IpSetSyncMode.SetAndEntries);
                sets.AddSet(set);

                foreach (var r in ranges)
                {
                    for (uint i = r.LowerPort; i <= r.UpperPort; i++)
                    {
                        set.Entries.Add(new IpSetEntry(set, null, null, (ushort)i));
                    }
                }

                if (set.Entries.Count == 0)
                {
                    throw new Exception("Entries should not be zero");
                }
            }
            else
            {
                set = sets.GetSetByName(setName);
            }

            var ipsetModule = rule.GetModuleOrLoad<SetMatchModule>("set");
            ipsetModule.MatchSetFlags = "dst";

            if (set.Entries.Count >= UInt16.MaxValue / 2)
            {
                HashSet<UInt16> ports = new HashSet<ushort>(set.Entries.Select(a => (UInt16)a.Port));
                set.Entries.Clear();
                for (UInt16 i = 1; i < UInt16.MaxValue; i++)
                {
                    if (!ports.Contains(i))
                        set.Entries.Add(new IpSetEntry(set, null, null, i));
                }

                if (set.Entries.Count == 0)
                {
                    set.Entries.Add(new IpSetEntry(set, null, null, 0)); // a hack
                }

                ipsetModule.MatchSet = new ValueOrNot<string>(setName, true);
            }
            else
            {
                ipsetModule.MatchSet = new ValueOrNot<string>(setName);
            }
        }
        public static void SourcePortSetter(IpTablesRule rule, List<PortOrRange> ranges)
        {
            var protocol = rule.GetModule<CoreModule>("core").Protocol;
            if (ranges.Count == 1 && !protocol.Null && !protocol.Not)
            {
                if (protocol.Value == "tcp")
                {
                    var tcp = rule.GetModuleOrLoad<TcpModule>("tcp");
                    tcp.SourcePort = new ValueOrNot<PortOrRange>(ranges[0]);
                }
                else
                {
                    var tcp = rule.GetModuleOrLoad<UdpModule>("udp");
                    tcp.SourcePort = new ValueOrNot<PortOrRange>(ranges[0]);
                }
            }
            else
            {
                var multiport = rule.GetModuleOrLoad<MultiportModule>("multiport");
                multiport.SourcePorts = new ValueOrNot<IEnumerable<PortOrRange>>(ranges);
            }
        }
    }
}
