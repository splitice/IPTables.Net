using System;
using SystemInteract;
using IPTables.Net.Iptables.Helpers;

namespace IPTables.Net.Iptables.Adapter.Client
{
    internal class IPTablesBinaryAdapterClient: IIPTablesAdapterClient
    {
        private readonly IpTablesSystem _system;

        public IPTablesBinaryAdapterClient(IpTablesSystem system)
        {
            _system = system;
        }

        public void DeleteRule(String table, String chainName, int position)
        {
            String command = "-D " + chainName + " " + position;
            if (!String.IsNullOrEmpty(table) && table != "filter")
            {
                command += " -t " + table;
            }

            ExecutionHelper.ExecuteIptables(_system, command);
        }

        public void DeleteRule(IpTablesRule rule)
        {
            String command = rule.GetFullCommand("-D");
            ExecutionHelper.ExecuteIptables(_system, command);
        }

        public void InsertRule(IpTablesRule rule)
        {
            String command = rule.GetFullCommand("-I");
            ExecutionHelper.ExecuteIptables(_system, command);
        }

        public void ReplaceRule(IpTablesRule rule)
        {
            String command = rule.GetFullCommand("-R");
            ExecutionHelper.ExecuteIptables(_system, command);
        }

        public void AddRule(IpTablesRule rule)
        {
            String command = rule.GetFullCommand();
            ExecutionHelper.ExecuteIptables(_system, command);
        }

        public bool HasChain(string table, string chainName)
        {
            throw new NotImplementedException();
        }

        public void AddChain(string table, string chainName)
        {
            String command = String.Format("-t {0} -N {1}", table, chainName);
            ExecutionHelper.ExecuteIptables(_system, command);
        }

        public void DeleteChain(string table, string chainName, bool flush = false)
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

        public IpTablesChainSet ListRules(String table)
        {
            ISystemProcess process = _system.System.StartProcess("iptables-save", String.Format("-c -t {0}", table));
            process.WaitForExit();
            return Helper.IPTablesSaveParser.GetRulesFromOutput(_system,process.StandardOutput.ReadToEnd(), table);
        }

        public void StartTransaction()
        {
            //No transaction support
        }

        public void EndTransactionCommit()
        {
            //No transaction support
        }

        public void EndTransactionRollback()
        {
            //No transaction support
        }
    }
}
