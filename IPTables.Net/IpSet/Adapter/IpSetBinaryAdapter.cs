using System.Collections.Generic;
using System.IO;
using SystemInteract;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.Helpers;
using Serilog;

namespace IPTables.Net.IpSet.Adapter
{
    public class IpSetBinaryAdapter
    {
        private const string BinaryName = "ipset";
        protected static readonly ILogger _log = IPTablesLogManager.GetLogger<IpSetBinaryAdapter>();

        private readonly ISystemFactory _system;

        private List<string> _transactionCommands = null;

        public bool InTransaction => _transactionCommands != null;

        public IpSetBinaryAdapter(ISystemFactory system)
        {
            _system = system;
        }

        private bool ExecuteTransaction()
        {
            string output, error;

            using (var process = _system.StartProcess(BinaryName, "restore"))
            {
                if (WriteStrings(_transactionCommands, process.StandardInput))
                {
                    process.StandardInput.Flush();
                    process.StandardInput.Close();
                    ProcessHelper.ReadToEnd(process, out output, out error);

                    //OK
                    if (process.ExitCode == 0) return true;
                }
                else
                {
                    ProcessHelper.ReadToEnd(process, out output, out error);
                }
            }

            error = error.Trim();
            if (error.Length != 0)
                throw new IpTablesNetException(string.Format("Failed to execute transaction: {0}", error));

            return false;
        }

        public bool RestoreSets(IEnumerable<IpSetSet> sets)
        {
            //ipset restore
            using (var process = _system.StartProcess(BinaryName, "restore"))
            {
                if (WriteSets(sets, process.StandardInput))
                {
                    process.StandardInput.Flush();
                    process.StandardInput.Close();
                    ProcessHelper.WaitForExit(process);

                    //OK
                    if (process.ExitCode != 0) return true;
                }

                return false;
            }
        }

        private bool WriteStrings(IEnumerable<string> strings, StreamWriter standardInput)
        {
            foreach (var set in strings)
            {
                if (!standardInput.BaseStream.CanWrite) return false;
                try
                {
                    _log.Information("IPSet: {set}", set);
                    standardInput.WriteLine(set);
                }
                catch (IOException)
                {
                    return false;
                }
            }

            return true;
        }

        private bool WriteSets(IEnumerable<IpSetSet> sets, StreamWriter standardInput)
        {
            foreach (var set in sets)
            {
                if (!standardInput.BaseStream.CanWrite) return false;
                var command = set.GetCommand();
                if (!WriteStrings(new List<string> {command}, standardInput)) return false;
                if (!WriteStrings(set.GetEntryCommands(), standardInput)) return false;
            }

            return true;
        }

        public virtual void SaveSets(IpSetSets sets, string setName = null)
        {
            var iptables = sets.System;
            //ipset save
            var args = "save";
            if (!string.IsNullOrEmpty(setName)) args += " " + ShellHelper.EscapeArguments(setName);
            using (var process = _system.StartProcess(BinaryName, args))
            {
                ProcessHelper.ReadToEnd(process, line =>
                {
                    if (line == null) return;
                    var trimmed = line.Trim();
                    if (trimmed.Length != 0) sets.Accept(trimmed, iptables);
                }, err => { });
            }
        }

        public virtual IpSetSets SaveSets(IpTablesSystem iptables, string setName = null)
        {
            var sets = new IpSetSets(iptables);

            SaveSets(sets, setName);

            return sets;
        }

        public void DestroySet(string name)
        {
            var command = string.Format("destroy {0}", name);

            if (InTransaction)
            {
                _transactionCommands.Add(command);
            }
            else
            {
                string output, error;
                using (var process = _system.StartProcess(BinaryName, command))
                {
                    ProcessHelper.ReadToEnd(process, out output, out error);

                    if (process.ExitCode != 0)
                        throw new IpTablesNetException(string.Format("Failed to destroy set: {0}", error));
                }
            }
        }

        public bool EndTransactionCommit()
        {
            var ret = true;
            if (_transactionCommands != null && _transactionCommands.Count != 0) ret = ExecuteTransaction();
            _transactionCommands = null;
            return ret;
        }

        public void StartTransaction()
        {
            _transactionCommands = new List<string>();
        }

        public void CreateSet(IpSetSet set)
        {
            var command = set.GetFullCommand();

            if (InTransaction)
                _transactionCommands.Add(command);
            else
                using (var process = _system.StartProcess(BinaryName, command))
                {
                    string output, error;
                    ProcessHelper.ReadToEnd(process, out output, out error);

                    if (process.ExitCode != 0)
                        throw new IpTablesNetException(string.Format("Failed to create set: {0}", error));
                }
        }

        public void AddEntry(IpSetEntry entry)
        {
            var command = entry.GetFullCommand();

            if (InTransaction)
                _transactionCommands.Add(command);
            else
                using (var process = _system.StartProcess(BinaryName, command))
                {
                    string output, error;
                    ProcessHelper.ReadToEnd(process, out output, out error);

                    if (process.ExitCode != 0)
                        throw new IpTablesNetException(string.Format("Failed to add entry: {0}", error));
                }
        }

        public void DeleteEntry(IpSetEntry entry)
        {
            var command = entry.GetFullCommand("del");

            if (InTransaction)
                _transactionCommands.Add(command);
            else
                using (var process = _system.StartProcess(BinaryName, command))
                {
                    string output, error;
                    ProcessHelper.ReadToEnd(process, out output, out error);

                    if (process.ExitCode != 0)
                        throw new IpTablesNetException(string.Format("Failed to delete entry: {0}", error));
                }
        }

        public void SwapSet(string what, string with)
        {
            var command = string.Format("swap {0} {1}", what, with);

            if (InTransaction)
                _transactionCommands.Add(command);
            else
                using (var process = _system.StartProcess(BinaryName, command))
                {
                    string output, error;
                    ProcessHelper.ReadToEnd(process, out output, out error);

                    if (process.ExitCode != 0)
                        throw new IpTablesNetException(string.Format("Failed to swap sets: {0}", error));
                }
        }
    }
}