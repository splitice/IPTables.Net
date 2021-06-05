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

        public ISystemFactory System => _iptables.System;

        public IPTablesBinaryAdapterClient(int ipVersion, IpTablesSystem iptables, string iptablesBinary)
        {
            _iptables = iptables;
            _iptablesBinary = iptablesBinary;
            _ipVersion = ipVersion;
        }

        public override void DeleteRule(string table, string chainName, int position)
        {
            var command = "-D " + chainName + " " + position;
            if (!string.IsNullOrEmpty(table) && table != "filter") command += " -t " + table;

            ExecutionHelper.ExecuteIptables(_iptables, command, _iptablesBinary);
        }

        public override void DeleteRule(IpTablesRule rule)
        {
            var command = rule.GetActionCommand("-D");
            ExecutionHelper.ExecuteIptables(_iptables, command, _iptablesBinary);
        }

        public override void InsertRule(IpTablesRule rule)
        {
            var command = rule.GetActionCommand("-I");
            ExecutionHelper.ExecuteIptables(_iptables, command, _iptablesBinary);
        }

        public override void ReplaceRule(IpTablesRule rule)
        {
            var command = rule.GetActionCommand("-R");
            ExecutionHelper.ExecuteIptables(_iptables, command, _iptablesBinary);
        }

        public override void AddRule(IpTablesRule rule)
        {
            var command = rule.GetActionCommand();
            AddRule(command);
        }

        public override void AddRule(string command)
        {
            ExecutionHelper.ExecuteIptables(_iptables, command, _iptablesBinary);
        }

        public override Version GetIptablesVersion()
        {
            string versionOutput, error;
            ExecutionHelper.ExecuteIptables(_iptables, "-V", _iptablesBinary, out versionOutput, out error);
            var r = new Regex(@"iptables v([0-9]+\.[0-9]+\.[0-9]+)");
            if (!r.IsMatch(versionOutput)) throw new IpTablesNetException("Unable to get version string");
            var match = r.Match(versionOutput);
            return new Version(match.Groups[1].Value);
        }

        public override bool HasChain(string table, string chainName)
        {
            var command = string.Format("-L {0} -t {1}", chainName, table);
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
            var command = string.Format("-t {0} -N {1}", table, chainName);
            ExecutionHelper.ExecuteIptables(_iptables, command, _iptablesBinary);
        }

        public override void DeleteChain(string table, string chainName, bool flush = false)
        {
            string arguments;
            if (flush)
            {
                arguments = string.Format("-t {0} -F {1}", table, chainName);
                ExecutionHelper.ExecuteIptables(_iptables, arguments, _iptablesBinary);
            }

            arguments = string.Format("-t {0} -X {1}", table, chainName);
            ExecutionHelper.ExecuteIptables(_iptables, arguments, _iptablesBinary);
        }

        public override IpTablesChainSet ListRules(string table)
        {
            using (
                var process = _iptables.System.StartProcess(_iptablesBinary + "-save",
                    string.Format("-c -t {0}", table)))
            {
                string output, error;
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