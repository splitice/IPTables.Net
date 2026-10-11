using System.Collections.Generic;
using System.IO;
using SystemInteract;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.Helpers;
using IPTables.Net.Supporting;
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

        private bool ExecuteTransaction() => ExecuteRestore(_transactionCommands);

        private bool ExecuteRestore(IEnumerable<string> commands)
        {
            using var process = _system.StartProcess(BinaryName, "restore");
            if (!WriteStrings(commands, process.StandardInput)) throw new IOException("Unable to write ipset restore input");
            process.StandardInput.Close();
            ProcessHelper.ReadToEnd(process, out var output, out var error);
            if (process.ExitCode == 0) return true;
            if (!string.IsNullOrWhiteSpace(error)) throw new IpTablesNetException("Failed to execute ipset restore: " + error.Trim());
            return false;
        }

        public bool RestoreSets(IEnumerable<IpSetSet> sets)
        {
            var commands = new List<string>();
            foreach (var set in sets)
            {
                commands.Add(set.GetFullCommand());
                foreach (var entry in set.Entries) commands.Add(entry.GetFullCommand());
            }
            return ExecuteRestore(commands);
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
                ProcessHelper.ReadToEnd(process, out var output, out var error);
                if (process.ExitCode != 0) throw new IpTablesNetException("Failed to save sets: " + error);
                foreach (var line in output.Split('\n'))
                    if (!string.IsNullOrWhiteSpace(line)) sets.Accept(line.Trim(), iptables);
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
            try { return _transactionCommands == null || _transactionCommands.Count == 0 || ExecuteTransaction(); }
            finally { _transactionCommands = null; }
        }

        public void EndTransactionRollback() => _transactionCommands = null;

        public void StartTransaction()
        {
            if (InTransaction) throw new IpTablesNetException("IPSet transaction already started");
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