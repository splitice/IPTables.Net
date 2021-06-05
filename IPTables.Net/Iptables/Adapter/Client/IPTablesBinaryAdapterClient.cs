using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using SystemInteract;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.Helpers;
using IPTables.Net.Netfilter;

namespace IPTables.Net.Iptables.Adapter.Client
{
    internal class IPTablesBinaryAdapterClient : IpTablesAdapterClientBase, IIPTablesAdapterClient
    {
        private readonly IpTablesSystem _iptables;
        private string _iptablesBinary;
        private int _ipVersion;

        public ISystemFactory System
        {
            get { return _iptables.System; }
        }

        public IPTablesBinaryAdapterClient(int ipVersion, IpTablesSystem iptables, String iptablesBinary)
        {
            _iptables = iptables;
            _iptablesBinary = iptablesBinary;
            _ipVersion = ipVersion;
        }

        public override void DeleteRule(String table, String chainName, int position)
        {
            String command = "-D " + chainName + " " + position;
            if (!String.IsNullOrEmpty(table) && table != "filter")
            {
                command += " -t " + table;
            }

            ExecutionHelper.ExecuteIptables(_iptables, command, _iptablesBinary);
        }

        public override void DeleteRule(IpTablesRule rule)
        {
            String command = rule.GetActionCommand("-D");
            ExecutionHelper.ExecuteIptables(_iptables, command, _iptablesBinary);
        }

        public override void InsertRule(IpTablesRule rule)
        {
            String command = rule.GetActionCommand("-I");
            ExecutionHelper.ExecuteIptables(_iptables, command, _iptablesBinary);
        }

        public override void ReplaceRule(IpTablesRule rule)
        {
            String command = rule.GetActionCommand("-R");
            ExecutionHelper.ExecuteIptables(_iptables, command, _iptablesBinary);
        }

        public override void AddRule(IpTablesRule rule)
        {
            String command = rule.GetActionCommand();
            AddRule(command);
        }

        public override void AddRule(String command)
        {
            ExecutionHelper.ExecuteIptables(_iptables, command, _iptablesBinary);
        }

        public override Version GetIptablesVersion()
        {
            String versionOutput, error;
            ExecutionHelper.ExecuteIptables(_iptables, "-V", _iptablesBinary, out versionOutput, out error);
            Regex r = new Regex(@"iptables v([0-9]+\.[0-9]+\.[0-9]+)");
            if (!r.IsMatch(versionOutput))
            {
                throw new IpTablesNetException("Unable to get version string");
            }
            var match = r.Match(versionOutput);
            return new Version(match.Groups[1].Value);
        }

        public override bool HasChain(string table, string chainName)
        {
            String command = String.Format("-L {0} -t {1}", chainName, table);
            try
            {
                ExecutionHelper.ExecuteIptables(_iptables, command, _iptablesBinary);
                return true;
            }
            catch (IpTablesNetException)
            {
                return false;
            }
        }

        public override void AddChain(string table, string chainName)
        {
            String command = String.Format("-t {0} -N {1}", table, chainName);
            ExecutionHelper.ExecuteIptables(_iptables, command, _iptablesBinary);
        }

        public override void DeleteChain(string table, string chainName, bool flush = false)
        {
            String arguments;
            if (flush)
            {
                arguments = String.Format("-t {0} -F {1}", table, chainName);
                ExecutionHelper.ExecuteIptables(_iptables, arguments, _iptablesBinary);
            }
            arguments = String.Format("-t {0} -X {1}", table, chainName);
            ExecutionHelper.ExecuteIptables(_iptables, arguments, _iptablesBinary);
        }

        public override IpTablesChainSet ListRules(String table)
        {
            using (
                ISystemProcess process = _iptables.System.StartProcess(_iptablesBinary + "-save",
                    String.Format("-c -t {0}", table)))
            {
                String output, error;
                ProcessHelper.ReadToEnd(process, out output, out error);
                return Helper.IPTablesSaveParser.GetRulesFromOutput(_iptables, output, table, _ipVersion);
            }
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

        public override void Dispose()
        {
        }
    }
}
