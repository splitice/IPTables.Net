using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Netfilter;

namespace IPTables.Net.NfTables
{
    public class NfTablesRule: INetfilterRule
    {
        private NfTablesChain _chain;
        private PacketCounters _packet;
        private int _ipVersion;

        public void DeleteRule(bool usingPosition = true)
        {
            throw new NotImplementedException();
        }

        public void AddRule()
        {
            throw new NotImplementedException();
        }

        public void DeleteRule(INetfilterAdapterClient client, bool usingPosition = true)
        {
            throw new NotImplementedException();
        }

        public void AddRule(INetfilterAdapterClient client)
        {
            throw new NotImplementedException();
        }

        public void ReplaceRule(INetfilterAdapterClient client, INetfilterRule with)
        {
            throw new NotImplementedException();
        }

        public int IpVersion
        {
            get { return _ipVersion; }
        }

        public void ReplaceRule(INetfilterRule with)
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
            set { _chain = (NfTablesChain)value; }
        }

        public INetfilterRule DeepClone()
        {
            throw new NotImplementedException();
        }

        public INetfilterRule ShallowClone()
        {
            throw new NotImplementedException();
        }

        public bool DebugEquals(INetfilterRule rule, bool debug)
        {
            throw new NotImplementedException();
        }

        public String Table
        {
            get { return _chain.Table; }
        }
    }
}
