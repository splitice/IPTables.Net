using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using SystemInteract;
using IPTables.Net.Exceptions;
using IPTables.Net.Netfilter;

namespace IPTables.Net.Iptables.IpSet.Adapter
{
    public class IpSetBinaryAdapter
    {
        private const String BinaryName = "ipset";

        private readonly NetfilterSystem _system;

        private List<String> _transactionCommands = null;

        public bool InTransaction
        {
            get { return _transactionCommands != null; }
        }

        public IpSetBinaryAdapter(NetfilterSystem system)
        {
            _system = system;
        }
        private bool ExecuteTransaction()
        {
            //ipset save
            ISystemProcess process = _system.System.StartProcess(BinaryName, "restore");
            if (WriteStrings(_transactionCommands, process.StandardInput))
            {
                process.StandardInput.Flush();
                process.StandardInput.Close();
                process.WaitForExit();

                //OK
                if (process.ExitCode != 0)
                {
                    return true;
                }
            }

            return false;
        }

        public bool RestoreSets(IEnumerable<IpSetSet> sets)
        {
            //ipset save
            ISystemProcess process = _system.System.StartProcess(BinaryName, "restore");
            if (WriteSets(sets,process.StandardInput))
            {
                process.StandardInput.Flush();
                process.StandardInput.Close();
                process.WaitForExit();

                //OK
                if (process.ExitCode != 0)
                {
                    return true;
                }
            }

            return false;
        }

        private bool WriteStrings(IEnumerable<String> strings, StreamWriter standardInput)
        {
            foreach (var set in strings)
            {
                if (!standardInput.BaseStream.CanWrite)
                {
                    return false;
                }
                standardInput.WriteLine(set);
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
                standardInput.WriteLine(set.GetCommand());
                foreach (var entry in set.GetEntryCommands())
                {
                    if (!standardInput.BaseStream.CanWrite)
                    {
                        return false;
                    }
                    standardInput.WriteLine(entry);
                }
            }

            return true;
        }

        public IpSetSets SaveSets()
        {
            ISystemProcess process = _system.System.StartProcess(BinaryName, "save");

            IpSetSets sets = new IpSetSets((IpTablesSystem)_system);

            while(process.StandardOutput.BaseStream.CanRead)
            {
                String line = process.StandardOutput.ReadLine();
                String[] split = line.Split(new char[] {' '});

                if (split.Length == 0)
                {
                    continue;
                }

                var command = split[0];
                var options = String.Join(" ", split.Skip(1).ToArray());

                switch (command)
                {
                    case "create":
                        var set = IpSetSet.Parse(options, (IpTablesSystem)_system);
                        sets.AddSet(set);
                        break;
                    case "add":
                        IpSetEntry.Parse(options, sets);
                        break;
                }
            }

            process.WaitForExit();

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
                var process = _system.System.StartProcess(BinaryName, command);
                process.WaitForExit();

                if (process.ExitCode != 0)
                {
                    throw new IpTablesNetException(String.Format("Failed to destroy set: {0}",
                        process.StandardError.ReadToEnd()));
                }
            }
        }

        public bool EndTransactionCommit()
        {
            bool ret = true;
            if (_transactionCommands != null)
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
                var process = _system.System.StartProcess(BinaryName, command);
                process.WaitForExit();

                if (process.ExitCode != 0)
                {
                    throw new IpTablesNetException(String.Format("Failed to create set: {0}",
                        process.StandardError.ReadToEnd()));
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
                var process = _system.System.StartProcess(BinaryName, command);
                process.WaitForExit();

                if (process.ExitCode != 0)
                {
                    throw new IpTablesNetException(String.Format("Failed to add entry: {0}",
                        process.StandardError.ReadToEnd()));
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
                var process = _system.System.StartProcess(BinaryName, command);
                process.WaitForExit();

                if (process.ExitCode != 0)
                {
                    throw new IpTablesNetException(String.Format("Failed to delete entry: {0}",
                        process.StandardError.ReadToEnd()));
                }
            }
        }
    }
}
