using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Netfilter;

namespace IPTables.Net.NfTables
{
    class NfTablesRule: INetfilterRule
    {
        private NfTablesChain _chain;
        private PacketCounters _packet;

        public void Delete(bool usingPosition = true)
        {
            throw new NotImplementedException();
        }

        public void Add()
        {
            throw new NotImplementedException();
        }

        public void Replace(INetfilterRule with)
        {
            throw new NotImplementedException();
        }

        public string ChainName
        {
            get { return _chain.Name; }
        }

        public PacketCounters Counters
        {
            get { return _packet; }
            set { _packet = value; }
        }

        INetfilterChain INetfilterRule.Chain
        {
            get { return _chain; }
        }

        public String Table
        {
            get { return _chain.Table; }
        }
    }
}
