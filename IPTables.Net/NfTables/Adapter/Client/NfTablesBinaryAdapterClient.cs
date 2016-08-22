using System;

namespace IPTables.Net.NfTables.Adapter.Client
{
    class NfTablesBinaryAdapterClient: NfTablesAdapterClientBase
    {
        private String _binary;

        public NfTablesBinaryAdapterClient(String binary = "nft")
        {
            _binary = binary;
        }

        public override void StartTransaction()
        {
            throw new NotImplementedException();
        }

        public override void EndTransactionCommit()
        {
            throw new NotImplementedException();
        }

        public override void EndTransactionRollback()
        {
            throw new NotImplementedException();
        }

        public override bool HasChain(string table, string chainName)
        {
            throw new NotImplementedException();
        }

        public override void AddChain(string table, string chainName)
        {
            throw new NotImplementedException();
        }

        public override void DeleteChain(string table, string chainName, bool flush = false)
        {
            throw new NotImplementedException();
        }

        public override void DeleteRule(string table, string chainName, int position)
        {
            throw new NotImplementedException();
        }

        public override NfTablesChainSet ListRules(string table)
        {
            throw new NotImplementedException();
        }

        public override void Dispose()
        {
        }

        public override void DeleteRule(NfTablesRule rule)
        {
            throw new NotImplementedException();
        }

        public override void InsertRule(NfTablesRule rule)
        {
            throw new NotImplementedException();
        }

        public override void ReplaceRule(NfTablesRule rule)
        {
            throw new NotImplementedException();
        }

        public override void AddRule(NfTablesRule rule)
        {
            throw new NotImplementedException();
        }
    }
}
