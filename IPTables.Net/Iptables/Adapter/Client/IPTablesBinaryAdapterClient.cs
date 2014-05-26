using System;
using SystemInteract;
using IPTables.Net.Iptables.Helpers;
using IPTables.Net.Netfilter;

namespace IPTables.Net.Iptables.Adapter.Client
{
    internal class IPTablesBinaryAdapterClient : IpTablesAdapterClientBase, IIPTablesAdapterClient
    {
        private readonly NetfilterSystem _system;

        public IPTablesBinaryAdapterClient(NetfilterSystem system)
        {
            _system = system;
        }

        public override void DeleteRule(String table, String chainName, int position)
        {
            String command = "-D " + chainName + " " + position;
            if (!String.IsNullOrEmpty(table) && table != "filter")
            {
                command += " -t " + table;
            }

            ExecutionHelper.ExecuteIptables(_system, command);
        }

        public override void DeleteRule(IpTablesRule rule)
        {
            String command = rule.GetFullCommand("-D");
            ExecutionHelper.ExecuteIptables(_system, command);
        }

        public override void InsertRule(IpTablesRule rule)
        {
            String command = rule.GetFullCommand("-I");
            ExecutionHelper.ExecuteIptables(_system, command);
        }

        public override void ReplaceRule(IpTablesRule rule)
        {
            String command = rule.GetFullCommand("-R");
            ExecutionHelper.ExecuteIptables(_system, command);
        }

        public override void AddRule(IpTablesRule rule)
        {
            String command = rule.GetFullCommand();
            ExecutionHelper.ExecuteIptables(_system, command);
        }

        public override bool HasChain(string table, string chainName)
        {
            throw new NotImplementedException();
        }

        public override void AddChain(string table, string chainName)
        {
            String command = String.Format("-t {0} -N {1}", table, chainName);
            ExecutionHelper.ExecuteIptables(_system, command);
        }

        public override void DeleteChain(string table, string chainName, bool flush = false)
        {
            String arguments;
            if (flush)
            {
                arguments = String.Format("-t {0} -F {1} -X {1}", table, chainName);
            }
            else
            {
                arguments = String.Format("-t {0} -X {1}", table, chainName);
            }
            ExecutionHelper.ExecuteIptables(_system, arguments);
        }

        public override IpTablesChainSet ListRules(String table)
        {
            ISystemProcess process = _system.System.StartProcess("iptables-save", String.Format("-c -t {0}", table));
            String output = "";
            do
            {
                output += process.StandardOutput.ReadToEnd();
            } while (!process.HasExited);
            process.WaitForExit();
            return Helper.IPTablesSaveParser.GetRulesFromOutput(_system, output, table);
        }

        public override void StartTransaction()
        {
            //No transaction support
        }

        public override void EndTransactionCommit()
        {
            //No transaction support
        }

        public override void EndTransactionRollback()
        {
            //No transaction support
        }
    }
}
