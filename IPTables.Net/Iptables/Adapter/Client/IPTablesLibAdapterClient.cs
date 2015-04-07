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

            GetInterface(table).ExecuteCommand(command);
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
            GetInterface(rule.Chain.Table).ExecuteCommand(command);
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
            GetInterface(rule.Chain.Table).ExecuteCommand(command);
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
            GetInterface(rule.Chain.Table).ExecuteCommand(command);
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
            GetInterface(rule.Chain.Table).ExecuteCommand(command);
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

            GetInterface(table).AddChain(chainName);
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

        public List<IpTablesRule> ListRulesInChain(String table, String chain)
        {
            List<IpTablesRule> ret = new List<IpTablesRule>();

            var ipc = GetInterface(table);

            foreach (var ipc_rule in ipc.GetRules(chain))
            {
                ret.Add(IpTablesRule.Parse(ipc.GetRuleString(chain, ipc_rule),_system,null,table));
            }

            return ret;
        } 

        public override IpTablesChainSet ListRules(String table)
        {
            IpTablesChainSet chains = new IpTablesChainSet();
            
            var ipc = GetInterface(table);

            foreach (String chain in ipc.GetChains())
            {
                chains.AddChain(new IpTablesChain(chain, table, _system, ListRulesInChain(table, chain)));
            }

            return null;
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
