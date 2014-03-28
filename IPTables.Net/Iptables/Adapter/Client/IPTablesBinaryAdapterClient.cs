using System;
using SystemInteract;

namespace IPTables.Net.Iptables.Adapter.Client
{
    public class IPTablesBinaryAdapterClient: IIPTablesAdapterClient
    {
        private readonly IpTablesSystem _system;

        public IPTablesBinaryAdapterClient(IpTablesSystem system)
        {
            _system = system;
        }

        public void Delete(String table, String chainName, int position)
        {
            String command = "-D " + chainName + " " + position;
            if (!String.IsNullOrEmpty(table) && table != "filter")
            {
                command += " -t " + table;
            }

            ExecutionHelper.ExecuteIptables(_system, command);
        }

        public void Delete(IpTablesRule rule)
        {
            String command = rule.GetFullCommand("-D");
            ExecutionHelper.ExecuteIptables(_system, command);
        }

        public void Insert(IpTablesRule rule)
        {
            String command = rule.GetFullCommand("-I");
            ExecutionHelper.ExecuteIptables(_system, command);
        }

        public void Replace(IpTablesRule rule)
        {
            String command = rule.GetFullCommand("-R");
            ExecutionHelper.ExecuteIptables(_system, command);
        }

        public void Add(IpTablesRule rule)
        {
            String command = rule.GetFullCommand();
            ExecutionHelper.ExecuteIptables(_system, command);
        }

        public IpTablesChainSet ListRules(String table)
        {
            ISystemProcess process = _system.System.StartProcess("iptables-save", String.Format("-c -t {0}", table));
            process.WaitForExit();
            return Helper.IPTablesSaveParser.GetRulesFromOutput(_system,process.StandardOutput.ReadToEnd(), table);
        }
    }
}
