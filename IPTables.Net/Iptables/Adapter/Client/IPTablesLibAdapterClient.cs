using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using SystemInteract;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.Adapter.Client.Helper;
using IPTables.Net.Iptables.NativeLibrary;
using IPTables.Net.Netfilter;

namespace IPTables.Net.Iptables.Adapter.Client
{
    internal class IPTablesLibAdapterClient : IpTablesAdapterClientBase, IIPTablesAdapterClient
    {
        private readonly NetfilterSystem _system;
        private bool _inTransaction = false;
        protected Dictionary<String, IptcInterface> _interfaces = new Dictionary<string, IptcInterface>();

        public IPTablesLibAdapterClient(NetfilterSystem system)
        {
            _system = system;
        }

        private IptcInterface GetInterface(String table)
        {
            if (_interfaces.ContainsKey(table))
            {
                return _interfaces[table];
            }

            var i = new IptcInterface(table);
            _interfaces.Add(table, i);
            return i;
        }


        public override void DeleteRule(String table, String chainName, int position)
        {
            if (!_inTransaction)
            {
                //Revert to using IPTables Binary if non transactional
                IPTablesBinaryAdapterClient binaryClient = new IPTablesBinaryAdapterClient(_system);
                binaryClient.DeleteRule(table, chainName, position);
            }

            String command = "-D " + chainName + " " + position;

            if (GetInterface(table).ExecuteCommand(command) != 1)
            {
                throw new IpTablesNetException(String.Format("Failed to delete rule \"{0}\" due to error: \"{1}\"", command, GetInterface(table).GetErrorString()));
            }
        }

        INetfilterChainSet INetfilterAdapterClient.ListRules(string table)
        {
            return ListRules(table);
        }

        public override void DeleteRule(IpTablesRule rule)
        {
            if (!_inTransaction)
            {
                //Revert to using IPTables Binary if non transactional
                IPTablesBinaryAdapterClient binaryClient = new IPTablesBinaryAdapterClient(_system);
                binaryClient.DeleteRule(rule);
            }

            String command = rule.GetActionCommand("-D", false);
            if (GetInterface(rule.Chain.Table).ExecuteCommand(command) != 1)
            {
                throw new IpTablesNetException(String.Format("Failed to delete rule \"{0}\" due to error: \"{1}\"", command, GetInterface(rule.Chain.Table).GetErrorString()));
            }
        }

        public override void InsertRule(IpTablesRule rule)
        {
            if (!_inTransaction)
            {
                //Revert to using IPTables Binary if non transactional
                IPTablesBinaryAdapterClient binaryClient = new IPTablesBinaryAdapterClient(_system);
                binaryClient.InsertRule(rule);
            }

            String command = rule.GetActionCommand("-I", false); 
            if (GetInterface(rule.Chain.Table).ExecuteCommand(command) != 1)
            {
                throw new IpTablesNetException(String.Format("Failed to insert rule \"{0}\" due to error: \"{1}\"", command, GetInterface(rule.Chain.Table).GetErrorString()));
            }
        }

        public override void ReplaceRule(IpTablesRule rule)
        {
            if (!_inTransaction)
            {
                //Revert to using IPTables Binary if non transactional
                IPTablesBinaryAdapterClient binaryClient = new IPTablesBinaryAdapterClient(_system);
                binaryClient.ReplaceRule(rule);
            }

            String command = rule.GetActionCommand("-R", false);
            if (GetInterface(rule.Chain.Table).ExecuteCommand(command) != 1)
            {
                throw new IpTablesNetException(String.Format("Failed to replace rule \"{0}\" due to error: \"{1}\"", command, GetInterface(rule.Chain.Table).GetErrorString()));
            }
        }

        public override void AddRule(IpTablesRule rule)
        {
            if (!_inTransaction)
            {
                //Revert to using IPTables Binary if non transactional
                IPTablesBinaryAdapterClient binaryClient = new IPTablesBinaryAdapterClient(_system);
                binaryClient.AddRule(rule);
            }

            String command = rule.GetActionCommand("-A", false);
            if (GetInterface(rule.Chain.Table).ExecuteCommand(command) != 1)
            {
                throw new IpTablesNetException(String.Format("Failed to add rule \"{0}\" due to error: \"{1}\"", command, GetInterface(rule.Chain.Table).GetErrorString()));
            }
        }

        public Version GetIptablesVersion()
        {
            IPTablesBinaryAdapterClient binaryClient = new IPTablesBinaryAdapterClient(_system);
            return binaryClient.GetIptablesVersion();
        }

        public override bool HasChain(string table, string chainName)
        {
            if (_inTransaction)
            {
                if (GetInterface(table).HasChain(chainName))
                {
                    return true;
                }
            }

            IPTablesBinaryAdapterClient binaryClient = new IPTablesBinaryAdapterClient(_system);
            return binaryClient.HasChain(table, chainName);
        }

        public override void AddChain(string table, string chainName)
        {
            if (!_inTransaction)
            {
                //Revert to using IPTables Binary if non transactional
                IPTablesBinaryAdapterClient binaryClient = new IPTablesBinaryAdapterClient(_system);
                binaryClient.AddChain(table, chainName);
            }

            if (!GetInterface(table).AddChain(chainName))
            {
                throw new IpTablesNetException(String.Format("Failed to add chain \"{0}\" to table \"{1}\" due to error: \"{2}\"", chainName, table, GetInterface(table).GetErrorString()));
            }
        }

        public override void DeleteChain(string table, string chainName, bool flush = false)
        {
            if (_inTransaction)
            {
                GetInterface(table).DeleteChain(chainName);
            }
            
            IPTablesBinaryAdapterClient binaryClient = new IPTablesBinaryAdapterClient(_system);
            binaryClient.DeleteChain(table, chainName);
        }

        public override IpTablesChainSet ListRules(String table)
        {
            IpTablesChainSet chains = new IpTablesChainSet();
            
            var ipc = GetInterface(table);

            foreach (String chain in ipc.GetChains())
            {
                foreach (var ipc_rule in ipc.GetRules(chain))
                {
                    chains.AddRule(IpTablesRule.Parse(ipc.GetRuleString(chain, ipc_rule), _system, chains, table, true));
                }
            }

            return chains;
        }

        public override void StartTransaction()
        {
            if (_inTransaction)
            {
                throw new IpTablesNetException("IPTables transaction already started");
            }
            _inTransaction = true;
        }

        public override void EndTransactionCommit()
        {
            if (!_inTransaction)
            {
                return;
            }

            foreach (var kv in _interfaces)
            {
                kv.Value.Commit();
            }
            _interfaces.Clear();
            
            _inTransaction = false;
        }

        public override void EndTransactionRollback()
        {
            _interfaces.Clear();
            _inTransaction = false;
        }

        ~IPTablesLibAdapterClient()
        {
            if (_inTransaction)
            {
                throw new IpTablesNetException("Transaction active, must be commited or rolled back.");
            }
        }
    }
}
