using System;
using System.Collections.Generic;
using SystemInteract;
using IPTables.Net.Iptables.Adapter.Client.Helper;

namespace IPTables.Net.Iptables.Adapter.Client
{
    internal class IPTablesRestoreAdapterClient : IIPTablesAdapterClient
    {
        private const String NoFlushOption = "--noflush";

        private readonly IpTablesSystem _system;
        private String _iptablesRestoreBinary;
        private bool _inTransaction = false;
        private IPTablesRestoreTableBuilder _builder = new IPTablesRestoreTableBuilder();

        public IPTablesRestoreAdapterClient(IpTablesSystem system, String iptablesRestoreBinary = "iptables-restore")
        {
            _system = system;
            _iptablesRestoreBinary = iptablesRestoreBinary;
        }

        public void DeleteRule(String table, String chainName, int position)
        {
            if (!_inTransaction)
            {
                //Revert to using IPTables Binary if non transactional
                IPTablesBinaryAdapterClient binaryClient = new IPTablesBinaryAdapterClient(_system);
                binaryClient.DeleteRule(table, chainName, position);
            }

            String command = "-D " + chainName + " " + position;

            _builder.AddCommand(table, command);
        }

        public void DeleteRule(IpTablesRule rule)
        {
            if (!_inTransaction)
            {
                //Revert to using IPTables Binary if non transactional
                IPTablesBinaryAdapterClient binaryClient = new IPTablesBinaryAdapterClient(_system);
                binaryClient.DeleteRule(rule);
            }

            String command = rule.GetFullCommand("-D");
            _builder.AddCommand(rule.Table, command);
        }

        public void InsertRule(IpTablesRule rule)
        {
            if (!_inTransaction)
            {
                //Revert to using IPTables Binary if non transactional
                IPTablesBinaryAdapterClient binaryClient = new IPTablesBinaryAdapterClient(_system);
                binaryClient.InsertRule(rule);
            }

            String command = rule.GetFullCommand("-I");
            _builder.AddCommand(rule.Table, command);
        }

        public void ReplaceRule(IpTablesRule rule)
        {
            if (!_inTransaction)
            {
                //Revert to using IPTables Binary if non transactional
                IPTablesBinaryAdapterClient binaryClient = new IPTablesBinaryAdapterClient(_system);
                binaryClient.ReplaceRule(rule);
            }

            String command = rule.GetFullCommand("-R");
            _builder.AddCommand(rule.Table, command);
        }

        public void AddRule(IpTablesRule rule)
        {
            if (!_inTransaction)
            {
                //Revert to using IPTables Binary if non transactional
                IPTablesBinaryAdapterClient binaryClient = new IPTablesBinaryAdapterClient(_system);
                binaryClient.AddRule(rule);
            }

            String command = rule.GetFullCommand();
            _builder.AddCommand(rule.Table, command);
        }

        public bool HasChain(string table, string chainName)
        {
            if (_inTransaction)
            {
                if (_builder.HasChain(table, chainName))
                {
                    return true;
                }
            }

            IPTablesBinaryAdapterClient binaryClient = new IPTablesBinaryAdapterClient(_system);
            return binaryClient.HasChain(table, chainName);
        }

        public void AddChain(string table, string chainName)
        {
            if (!_inTransaction)
            {
                //Revert to using IPTables Binary if non transactional
                IPTablesBinaryAdapterClient binaryClient = new IPTablesBinaryAdapterClient(_system);
                binaryClient.AddChain(table, chainName);
            }

            _builder.AddChain(table, chainName);
        }

        public void DeleteChain(string table, string chainName, bool flush = false)
        {
            if (_inTransaction)
            {
                _builder.DeleteChain(table, chainName);
            }
            
            IPTablesBinaryAdapterClient binaryClient = new IPTablesBinaryAdapterClient(_system);
            binaryClient.DeleteChain(table, chainName);
        }

        public IpTablesChainSet ListRules(String table)
        {
            ISystemProcess process = _system.System.StartProcess("iptables-save", String.Format("-c -t {0}", table));
            process.WaitForExit();
            return Helper.IPTablesSaveParser.GetRulesFromOutput(_system,process.StandardOutput.ReadToEnd(), table);
        }

        public void StartTransaction()
        {
            if (_inTransaction)
            {
                throw new Exception("IPTables transaction already started");
            }
            _inTransaction = true;
        }

        public void EndTransactionCommit()
        {
            ISystemProcess process = _system.System.StartProcess(_iptablesRestoreBinary, NoFlushOption);
            _builder.WriteOutput(process.StandardInput);
            process.WaitForExit();

            //OK
            if (process.ExitCode != 0)
            {

                //ERR: INVALID COMMAND LINE
                if (process.ExitCode == 2)
                {
                    throw new Exception("IpTables-Restore execution failed: Invalid Command Line");
                }

                //ERR: GENERAL ERROR
                if (process.ExitCode == 1)
                {
                    throw new Exception("IpTables-Restore execution failed: Error");
                }

                //ERR: UNKNOWN
                throw new Exception("IpTables-Restore execution failed: Unknown Error");
            }

            _inTransaction = false;
        }

        public void EndTransactionRollback()
        {
            _builder.Clear();
            _inTransaction = false;
        }

        ~IPTablesRestoreAdapterClient()
        {
            if (_inTransaction)
            {
                throw new Exception("Transaction active, must be commited or rolled back.");
            }
        }
    }
}
