using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using SystemInteract;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.Adapter.Client.Helper;
using IPTables.Net.Netfilter;

namespace IPTables.Net.Iptables.Adapter.Client
{
    internal class IPTablesRestoreAdapterClient : IpTablesAdapterClientBase, IIPTablesAdapterClient
    {
        private const String NoFlushOption = "--noflush";
        private const String NoClearOption = "--noclear";

        private readonly NetfilterSystem _system;
        private readonly String _iptablesRestoreBinary;
        private readonly String _iptablesSaveBinary;
        private bool _inTransaction = false;
        protected IPTablesRestoreTableBuilder _builder = new IPTablesRestoreTableBuilder();
        private string _iptablesBinary;
        private int _ipVersion;

        public IPTablesRestoreAdapterClient(int ipVersion, NetfilterSystem system, String iptablesRestoreBinary = "iptables-restore", String iptableSaveBinary = "iptables-save", String iptablesBinary = "iptables")
        {
            _system = system;
            _iptablesRestoreBinary = iptablesRestoreBinary;
            _iptablesSaveBinary = iptableSaveBinary;
            _iptablesBinary = iptablesBinary;
            _ipVersion = ipVersion;
        }

        private ISystemProcess StartProcess(String binary, String arguments)
        {
            binary = binary.TrimStart();
            //-1 or 0
            if (binary.IndexOf(" ") > 0)
            {
                var splitBinary = binary.Split(new char[] { ' ' });
                binary = splitBinary[0];
                arguments = String.Join(" ",splitBinary.Skip(1).ToArray()) + " " + arguments;
            }
            return _system.System.StartProcess(binary, arguments);
        }

        public void CheckBinary()
        {
            using (var process = StartProcess(_iptablesRestoreBinary, "--help"))
            {
                String output, error;
                ProcessHelper.ReadToEnd(process, out output, out error);
                if (!error.Contains(NoClearOption))
                {
                    throw new IpTablesNetException(
                        "iptables-restore client is not compiled from patched source (patch-iptables-restore.diff)");
                }
            }
        }

        public override void DeleteRule(String table, String chainName, int position)
        {
            if (!_inTransaction)
            {
                //Revert to using IPTables Binary if non transactional
                IPTablesBinaryAdapterClient binaryClient = new IPTablesBinaryAdapterClient(_ipVersion, _system, _iptablesBinary);
                binaryClient.DeleteRule(table, chainName, position);
                return;
            }

            String command = "-D " + chainName + " " + position;

            _builder.AddCommand(table, command);
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
                IPTablesBinaryAdapterClient binaryClient = new IPTablesBinaryAdapterClient(_ipVersion, _system, _iptablesBinary);
                binaryClient.DeleteRule(rule);
                return;
            }

            String command = rule.GetActionCommand("-D", false);
            _builder.AddCommand(rule.Chain.Table, command);
        }

        public override void InsertRule(IpTablesRule rule)
        {
            if (!_inTransaction)
            {
                //Revert to using IPTables Binary if non transactional
                IPTablesBinaryAdapterClient binaryClient = new IPTablesBinaryAdapterClient(_ipVersion, _system, _iptablesBinary);
                binaryClient.InsertRule(rule);
                return;
            }

            String command = rule.GetActionCommand("-I", false);
            _builder.AddCommand(rule.Chain.Table, command);
        }

        public override void ReplaceRule(IpTablesRule rule)
        {
            if (!_inTransaction)
            {
                //Revert to using IPTables Binary if non transactional
                IPTablesBinaryAdapterClient binaryClient = new IPTablesBinaryAdapterClient(_ipVersion, _system, _iptablesBinary);
                binaryClient.ReplaceRule(rule);
            }

            String command = rule.GetActionCommand("-R", false);
            _builder.AddCommand(rule.Chain.Table, command);
        }

        public override void AddRule(IpTablesRule rule)
        {
            if (!_inTransaction)
            {
                //Revert to using IPTables Binary if non transactional
                IPTablesBinaryAdapterClient binaryClient = new IPTablesBinaryAdapterClient(_ipVersion, _system, _iptablesBinary);
                binaryClient.AddRule(rule);
                return;
            }

            String command = rule.GetActionCommand("-A", false);
            _builder.AddCommand(rule.Chain.Table, command);
        }

        public Version GetIptablesVersion()
        {
            IPTablesBinaryAdapterClient binaryClient = new IPTablesBinaryAdapterClient(_ipVersion, _system, _iptablesBinary);
            return binaryClient.GetIptablesVersion();
        }

        public override bool HasChain(string table, string chainName)
        {
            if (_inTransaction)
            {
                if (_builder.HasChain(table, chainName))
                {
                    return true;
                }
                return false;
            }

            IPTablesBinaryAdapterClient binaryClient = new IPTablesBinaryAdapterClient(_ipVersion, _system, _iptablesBinary);
            return binaryClient.HasChain(table, chainName);
        }

        public override void AddChain(string table, string chainName)
        {
            if (!_inTransaction)
            {
                //Revert to using IPTables Binary if non transactional
                IPTablesBinaryAdapterClient binaryClient = new IPTablesBinaryAdapterClient(_ipVersion, _system, _iptablesBinary);
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

            IPTablesBinaryAdapterClient binaryClient = new IPTablesBinaryAdapterClient(_ipVersion, _system, _iptablesBinary);
            binaryClient.DeleteChain(table, chainName);
        }

        public override IpTablesChainSet ListRules(String table)
        {
            using (ISystemProcess process = StartProcess(_iptablesSaveBinary, String.Format("-c -t {0}", table)))
            {
                String toEnd, error;
                ProcessHelper.ReadToEnd(process, out toEnd, out error);
                return Helper.IPTablesSaveParser.GetRulesFromOutput(_system, toEnd, table, _ipVersion);
            }
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

            using (ISystemProcess process = StartProcess(_iptablesRestoreBinary, NoFlushOption + " " + NoClearOption))
            {
                if (_builder.WriteOutput(process.StandardInput))
                {
                    process.StandardInput.Flush();
                    process.StandardInput.Close();
                    String output, error;
                    ProcessHelper.ReadToEnd(process, out output, out error);

                    //OK
                    if (process.ExitCode != 0)
                    {
                        //ERR: INVALID COMMAND LINE
                        if (process.ExitCode == 2)
                        {
                            MemoryStream ms = new MemoryStream();
                            var sw = new StreamWriter(ms);
                            _builder.WriteOutput(sw);
                            sw.Flush();
                            ms.Seek(0, SeekOrigin.Begin);
                            var sr = new StreamReader(ms);
                            Log.Error("Error invalid command line: " + sr.ReadToEnd());
                            throw new IpTablesNetException(
                                "IpTables-Restore execution failed: Invalid Command Line - " +
                                process.StandardError.ReadToEnd());
                        }

                        //ERR: GENERAL ERROR
                        if (process.ExitCode == 1)
                        {
                            Log.Error("An General Error Occured: " + error);

                            MemoryStream ms = new MemoryStream();
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
            if (_inTransaction)
            {
                throw new IpTablesNetException("Transaction active, must be commited or rolled back.");
            }
        }
    }
}
