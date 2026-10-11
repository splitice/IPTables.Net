using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using SystemInteract;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.Adapter.Client.Helper;

namespace IPTables.Net.Iptables.Adapter.Client
{
    internal class IPTablesRestoreAdapterClient : IpTablesAdapterClientBase, IIPTablesAdapterClient
    {
        private const string NoFlushOption = "--noflush";
        private const string NoClearOption = "--noclear";

        private readonly IpTablesSystem _system;
        private readonly string _iptablesRestoreBinary;
        private readonly string _iptablesSaveBinary;
        protected bool _inTransaction = false;
        protected IPTablesRestoreTableBuilder _builder = new IPTablesRestoreTableBuilder();
        private string _iptablesBinary;
        private int _ipVersion;

        public IPTablesRestoreAdapterClient(int ipVersion, IpTablesSystem system,
            string iptablesRestoreBinary = "iptables-restore", string iptableSaveBinary = "iptables-save",
            string iptablesBinary = "iptables")
        {
            _system = system;
            _iptablesRestoreBinary = iptablesRestoreBinary;
            _iptablesSaveBinary = iptableSaveBinary;
            _iptablesBinary = iptablesBinary;
            _ipVersion = ipVersion;
        }

        private ISystemProcess StartProcess(string binary, string arguments)
        {
            binary = binary.TrimStart();
            //-1 or 0
            if (binary.IndexOf(" ") > 0)
            {
                var splitBinary = binary.Split(new char[] {' '});
                binary = splitBinary[0];
                arguments = string.Join(" ", splitBinary.Skip(1).ToArray()) + " " + arguments;
            }

            return _system.System.StartProcess(binary, arguments);
        }

        public void CheckBinary()
        {
            using (var process = StartProcess(_iptablesRestoreBinary, "--help"))
            {
                string output, error;
                ProcessHelper.ReadToEnd(process, out output, out error);
                if (process.ExitCode != 0 || !(output + error).Contains(NoClearOption))
                    throw new IpTablesNetException(
                        "iptables-restore client is not compiled from patched source (patch-iptables-restore.diff)");
            }
        }

        public override void DeleteRule(string table, string chainName, int position)
        {
            if (!_inTransaction)
            {
                //Revert to using IPTables Binary if non transactional
                var binaryClient = new IPTablesBinaryAdapterClient(_ipVersion, _system, _iptablesBinary);
                binaryClient.DeleteRule(table, chainName, position);
                return;
            }

            var command = "-D " + chainName + " " + position;

            _builder.AddCommand(table, command);
        }

        public override void DeleteRule(IpTablesRule rule)
        {
            if (!_inTransaction)
            {
                //Revert to using IPTables Binary if non transactional
                var binaryClient = new IPTablesBinaryAdapterClient(_ipVersion, _system, _iptablesBinary);
                binaryClient.DeleteRule(rule);
                return;
            }

            var command = rule.GetActionCommand("-D", false);
            _builder.AddCommand(rule.Chain.Table, command);
        }

        public override void InsertRule(IpTablesRule rule)
        {
            if (!_inTransaction)
            {
                //Revert to using IPTables Binary if non transactional
                var binaryClient = new IPTablesBinaryAdapterClient(_ipVersion, _system, _iptablesBinary);
                binaryClient.InsertRule(rule);
                return;
            }

            var command = rule.GetActionCommand("-I", false, true);
            _builder.AddCommand(rule.Chain.Table, command);
        }

        public override void ReplaceRule(IpTablesRule rule)
        {
            if (!_inTransaction)
            {
                //Revert to using IPTables Binary if non transactional
                var binaryClient = new IPTablesBinaryAdapterClient(_ipVersion, _system, _iptablesBinary);
                binaryClient.ReplaceRule(rule);
                return;
            }

            var command = rule.GetActionCommand("-R", false, true);
            _builder.AddCommand(rule.Chain.Table, command);
        }

        public override void AddRule(IpTablesRule rule)
        {
            if (!_inTransaction)
            {
                //Revert to using IPTables Binary if non transactional
                var binaryClient = new IPTablesBinaryAdapterClient(_ipVersion, _system, _iptablesBinary);
                binaryClient.AddRule(rule);
                return;
            }

            var command = rule.GetActionCommand("-A", false, true);
            _builder.AddCommand(rule.Chain.Table, command);
        }

        public override void AddRule(string command)
        {
            if (!_inTransaction)
            {
                new IPTablesBinaryAdapterClient(_ipVersion, _system, _iptablesBinary).AddRule(command);
                return;
            }
            var table = ExtractTable(command);
            _builder.AddCommand(table, command);
        }

        public override Version GetIptablesVersion()
        {
            var binaryClient = new IPTablesBinaryAdapterClient(_ipVersion, _system, _iptablesBinary);
            return binaryClient.GetIptablesVersion();
        }

        public override bool HasChain(string table, string chainName)
        {
            if (_inTransaction)
            {
                if (_builder.HasChain(table, chainName)) return true;
                return false;
            }

            var binaryClient = new IPTablesBinaryAdapterClient(_ipVersion, _system, _iptablesBinary);
            return binaryClient.HasChain(table, chainName);
        }

        public override void AddChain(string table, string chainName)
        {
            if (!_inTransaction)
            {
                //Revert to using IPTables Binary if non transactional
                var binaryClient = new IPTablesBinaryAdapterClient(_ipVersion, _system, _iptablesBinary);
                binaryClient.AddChain(table, chainName);
                return;
            }

            _builder.AddChain(table, chainName);
        }

        public override void DeleteChain(string table, string chainName, bool flush = false)
        {
            if (_inTransaction)
            {
                if (!_builder.DeleteChain(table, chainName))
                {
                    if (flush) _builder.AddCommand(table, "-F " + chainName);
                    _builder.AddCommand(table, "-X " + chainName);
                }
                return;
            }

            var binaryClient = new IPTablesBinaryAdapterClient(_ipVersion, _system, _iptablesBinary);
            binaryClient.DeleteChain(table, chainName, flush);
        }

        public override IpTablesChainSet ListRules(string table)
        {
            using (var process = StartProcess(_iptablesSaveBinary, string.Format("-c -t {0}", table)))
            {
                string toEnd, error;
                ProcessHelper.ReadToEnd(process, out toEnd, out error);
                if (process.ExitCode != 0) throw new IpTablesNetException(error);
                return IPTablesSaveParser.GetRulesFromOutput(_system, toEnd, table, _ipVersion);
            }
        }

        public override void StartTransaction()
        {
            if (_inTransaction) throw new IpTablesNetException("IPTables transaction already started");
            _inTransaction = true;
        }

        public override void EndTransactionCommit()
        {
            if (!_inTransaction) return;
            using var buffer = new MemoryStream();
            using (var writer = new StreamWriter(buffer, new System.Text.UTF8Encoding(false), 1024, true))
            {
                _builder.WriteOutput(writer);
                writer.Flush();
            }
            var rules = System.Text.Encoding.UTF8.GetString(buffer.ToArray());
            if (rules.Length != 0)
            {
                using var process = StartProcess(_iptablesRestoreBinary, NoFlushOption + " " + NoClearOption);
                process.StandardInput.Write(rules);
                process.StandardInput.Close();
                ProcessHelper.ReadToEnd(process, out var output, out var error);
                if (process.ExitCode != 0)
                {
                    var line = Regex.Match(error, @"line ([0-9]+) failed");
                    string context = "";
                    if (line.Success && int.TryParse(line.Groups[1].Value, out var number))
                        context = rules.Split('\n').ElementAtOrDefault(number - 1) ?? "";
                    throw new IpTablesNetException($"IpTables-Restore execution failed (exit {process.ExitCode}): {error} {context}".Trim());
                }
            }
            _builder.Clear();
            _inTransaction = false;
        }

        public override void EndTransactionRollback()
        {
            _builder.Clear();
            _inTransaction = false;
        }



        public override void Dispose()
        {
            if (_inTransaction) throw new IpTablesNetException("Transaction active, must be commited or rolled back.");
        }
    }
}
