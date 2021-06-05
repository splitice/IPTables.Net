using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Netfilter
{
    public struct PacketCounters
    {
        public long Bytes;
        public long Packets;

        public PacketCounters(long bytes, long packets)
        {
            Bytes = bytes;
            Packets = packets;
        }

        public bool IsCounting()
        {
            return Bytes != -1 || Packets != -1;
        }

        private static PacketCounters NotCounting()
        {
            return new PacketCounters {Bytes = -1, Packets = -1};
        }
    }
}