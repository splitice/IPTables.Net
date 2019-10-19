using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using SystemInteract;
using IPTables.Net.Exceptions;
using IPTables.Net.Netfilter;
using log4net;

namespace IPTables.Net.Iptables.IpSet.Adapter
{
    public class IpSetBinaryAdapter
    {
        private const String BinaryName = "ipset";
        protected static readonly ILog _log = LogManager.GetLogger(typeof(IpSetBinaryAdapter));

        private readonly ISystemFactory _system;

        private List<String> _transactionCommands = null;

        public bool InTransaction
        {
            get { return _transactionCommands != null; }
        }

        public IpSetBinaryAdapter(ISystemFactory system)
        {
            _system = system;
        }
        private bool ExecuteTransaction()
        {
            String output, error;

            using (ISystemProcess process = _system.StartProcess(BinaryName, "restore"))
            {

                if (WriteStrings(_transactionCommands, process.StandardInput))
                {
                    process.StandardInput.Flush();
                    process.StandardInput.Close();
                    ProcessHelper.ReadToEnd(process, out output, out error);

                    //OK
                    if (process.ExitCode == 0)
                    {
                        return true;
                    }
                }
                else
                {
                    ProcessHelper.ReadToEnd(process, out output, out error);
                }
            }

            error = error.Trim();
            if (error.Length != 0)
            {
                throw new IpTablesNetException(String.Format("Failed to execute transaction: {0}", error));
            }

            return false;
        }

        public bool RestoreSets(IEnumerable<IpSetSet> sets)
        {
            //ipset restore
            using (ISystemProcess process = _system.StartProcess(BinaryName, "restore"))
            {
                if (WriteSets(sets, process.StandardInput))
                {
                    process.StandardInput.Flush();
                    process.StandardInput.Close();
                    ProcessHelper.WaitForExit(process);

                    //OK
                    if (process.ExitCode != 0)
                    {
                        return true;
                    }
                }

                return false;
            }
        }

        private bool WriteStrings(IEnumerable<String> strings, StreamWriter standardInput)
        {
            foreach (var set in strings)
            {
                if (!standardInput.BaseStream.CanWrite)
                {
                    return false;
                }
                try
                {
                    _log.InfoFormat("IPSet: {0}", set);
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
                if (!standardInput.BaseStream.CanWrite)
                {
                    return false;
                }
                var command = set.GetCommand();
                if (!WriteStrings(new List<string> {command}, standardInput))
                {
                    return false;
                }
                if (!WriteStrings(set.GetEntryCommands(), standardInput))
                {
                    return false;
                }
            }

            return true;
        }

        public virtual IpSetSets SaveSets(IpTablesSystem iptables)
        {
            IpSetSets sets = new IpSetSets(iptables);

            //ipset save
            using (ISystemProcess process = _system.StartProcess(BinaryName, "save"))
            {
                ProcessHelper.ReadToEnd(process, line =>
                {
                    if (line == null) return;
                    var trimmed = line.Trim();
                    if (trimmed.Length != 0)
                    {
                        sets.Accept(trimmed, iptables);
                    }
                }, err=>{ });
            }
            
            return sets;
        }

        public void DestroySet(String name)
        {
            String command = String.Format("destroy {0}", name);

            if (InTransaction)
            {
                _transactionCommands.Add(command);
            }
            else
            {
                String output, error;
                using (var process = _system.StartProcess(BinaryName, command))
                {
                    ProcessHelper.ReadToEnd(process, out output, out error);

                    if (process.ExitCode != 0)
                    {
                        throw new IpTablesNetException(String.Format("Failed to destroy set: {0}", error));
                    }
                }
            }
        }

        public bool EndTransactionCommit()
        {
            bool ret = true;
            if (_transactionCommands != null && _transactionCommands.Count != 0)
            {
                ret = ExecuteTransaction();
            }
            _transactionCommands = null;
            return ret;
        }

        public void StartTransaction()
        {
            _transactionCommands = new List<string>();
        }

        public void CreateSet(IpSetSet set)
        {
            String command = set.GetFullCommand();

            if (InTransaction)
            {
                _transactionCommands.Add(command);
            }
            else
            {
                using (var process = _system.StartProcess(BinaryName, command))
                {

                    String output, error;
                    ProcessHelper.ReadToEnd(process, out output, out error);

                    if (process.ExitCode != 0)
                    {
                        throw new IpTablesNetException(String.Format("Failed to create set: {0}", error));
                    }
                }
            }
        }

        public void AddEntry(IpSetEntry entry)
        {
            String command = entry.GetFullCommand();

            if (InTransaction)
            {
                _transactionCommands.Add(command);
            }
            else
            {
                using (var process = _system.StartProcess(BinaryName, command))
                {
                    String output, error;
                    ProcessHelper.ReadToEnd(process, out output, out error);

                    if (process.ExitCode != 0)
                    {
                        throw new IpTablesNetException(String.Format("Failed to add entry: {0}", error));
                    }
                }
            }
        }

        public void DeleteEntry(IpSetEntry entry)
        {
            String command = entry.GetFullCommand("del");

            if (InTransaction)
            {
                _transactionCommands.Add(command);
            }
            else
            {
                using (var process = _system.StartProcess(BinaryName, command))
                {
                    String output, error;
                    ProcessHelper.ReadToEnd(process, out output, out error);

                    if (process.ExitCode != 0)
                    {
                        throw new IpTablesNetException(String.Format("Failed to delete entry: {0}", error));
                    }
                }
            }
        }
    }
}
