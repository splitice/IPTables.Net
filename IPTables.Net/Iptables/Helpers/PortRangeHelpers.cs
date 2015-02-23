using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

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

            int count = 0, ruleCount = ports.Count != 0 ? 1 : 0;
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
    }
}
