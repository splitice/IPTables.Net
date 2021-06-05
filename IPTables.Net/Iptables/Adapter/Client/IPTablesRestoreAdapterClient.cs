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
                if (!error.Contains(NoClearOption))
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

            var command = rule.GetActionCommand("-I", false);
            _builder.AddCommand(rule.Chain.Table, command);
        }

        public override void ReplaceRule(IpTablesRule rule)
        {
            if (!_inTransaction)
            {
                //Revert to using IPTables Binary if non transactional
                var binaryClient = new IPTablesBinaryAdapterClient(_ipVersion, _system, _iptablesBinary);
                binaryClient.ReplaceRule(rule);
            }

            var command = rule.GetActionCommand("-R", false);
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

            var command = rule.GetActionCommand("-A", false);
            _builder.AddCommand(rule.Chain.Table, command);
        }

        public override void AddRule(string command)
        {
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
            }

            _builder.AddChain(table, chainName);
        }

        public override void DeleteChain(string table, string chainName, bool flush = false)
        {
            if (_inTransaction)
            {
                _builder.DeleteChain(table, chainName);
                return;
            }

            var binaryClient = new IPTablesBinaryAdapterClient(_ipVersion, _system, _iptablesBinary);
            binaryClient.DeleteChain(table, chainName);
        }

        public override IpTablesChainSet ListRules(string table)
        {
            using (var process = StartProcess(_iptablesSaveBinary, string.Format("-c -t {0}", table)))
            {
                string toEnd, error;
                ProcessHelper.ReadToEnd(process, out toEnd, out error);
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

            using (var process = StartProcess(_iptablesRestoreBinary, NoFlushOption + " " + NoClearOption))
            {
                if (_builder.WriteOutput(process.StandardInput))
                {
                    process.StandardInput.Flush();
                    process.StandardInput.Close();
                    string output, error;
                    ProcessHelper.ReadToEnd(process, out output, out error);

                    //OK
                    if (process.ExitCode != 0)
                    {
                        //ERR: INVALID COMMAND LINE
                        if (process.ExitCode == 2)
                        {
                            var ms = new MemoryStream();
                            var sw = new StreamWriter(ms);
                            _builder.WriteOutput(sw);
                            sw.Flush();
                            ms.Seek(0, SeekOrigin.Begin);
                            var sr = new StreamReader(ms);
                            Log.Error("Error invalid command line: {error}", sr.ReadToEnd());
                            throw new IpTablesNetException(
                                "IpTables-Restore execution failed: Invalid Command Line - " +
                                process.StandardError.ReadToEnd());
                        }

                        //ERR: GENERAL ERROR
                        if (process.ExitCode == 1)
                        {
                            Log.Error("An General Error Occured: {error}", error);

                            var ms = new MemoryStream();
                            var sw = new StreamWriter(ms);
                            _builder.WriteOutput(sw);
                            sw.Flush();
                            ms.Seek(0, SeekOrigin.Begin);
                            var sr = new StreamReader(ms);
                            var rules = sr.ReadToEnd();

                            var r = new Regex("line ([0-9]+) failed");
                            if (r.IsMatch(error))
                            {
                                var m = r.Match(error);
                                var g = m.Groups[1];
                                var i = int.Parse(g.Value);

                                throw new IpTablesNetException("IpTables-Restore failed to parse rule: " +
                                                               rules.Split(new char[] {'\n'})
                                                                   .Skip(i - 1)
                                                                   .FirstOrDefault());
                            }

                            throw new IpTablesNetException("IpTables-Restore execution failed: Error");
                        }

                        //ERR: UNKNOWN
                        throw new IpTablesNetException("IpTables-Restore execution failed: Unknown Error");
                    }
                }

                try
                {
                    process.Close();
                }
                catch
                {
                }
            }


            _inTransaction = false;
        }

        public override void EndTransactionRollback()
        {
            _builder.Clear();
            _inTransaction = false;
        }

        ~IPTablesRestoreAdapterClient()
        {
            Dispose();
        }


        public override void Dispose()
        {
            if (_inTransaction) throw new IpTablesNetException("Transaction active, must be commited or rolled back.");
        }
    }
}