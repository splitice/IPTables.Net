using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;


namespace IPTables.Net.DataTypes
{
    struct CounterPacketsAndBytes
    {
        public uint Packets;
        public uint Bytes;

        public CounterPacketsAndBytes(uint packets, uint bytes)
        {
            Packets = packets;
            Bytes = bytes;
        }
    }
}
