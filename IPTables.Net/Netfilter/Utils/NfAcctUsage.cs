using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Netfilter.Utils
{
    public class NfAcctUsage
    {
        private string _name;
        private ulong _bytes;
        private ulong _packets;

        public NfAcctUsage(string name, ulong bytes, ulong packets)
        {
            Name = name;
            _bytes = bytes;
            _packets = packets;
        }

        public ulong Bytes
        {
            get => _bytes;
            set => _bytes = value;
        }

        public ulong Packets
        {
            get => _packets;
            set => _packets = value;
        }

        public string Name
        {
            get => _name;
            set => _name = value;
        }
    }
}