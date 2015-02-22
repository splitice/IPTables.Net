using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Helpers
{
    public class PortRangeCompression
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
    }
}
