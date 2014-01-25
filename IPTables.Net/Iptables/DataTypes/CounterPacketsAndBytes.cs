namespace IPTables.Net.Iptables.DataTypes
{
    internal struct CounterPacketsAndBytes
    {
        public uint Bytes;
        public uint Packets;

        public CounterPacketsAndBytes(uint packets, uint bytes)
        {
            Packets = packets;
            Bytes = bytes;
        }
    }
}