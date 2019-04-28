using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.IpSet.Adapter;
using IPTables.Net.Supporting;

namespace IPTables.Net.Iptables.IpSet
{
    public class IpSetSets
    {
        private Dictionary<String, IpSetSet> _sets = new Dictionary<String, IpSetSet>();
        private IpTablesSystem _system;

        public IpSetSets(IEnumerable<String> commands, IpTablesSystem system)
        {
            _system = system;
            foreach (var command in commands)
            {
                Accept(command, system);
            }
        }

        public IpSetSets(IpTablesSystem system)
        {
            _system = system;
        }

        public IEnumerable<IpSetSet> Sets
        {
            get { return _sets.Values; }
        }

        public IpTablesSystem System
        {
            get { return _system; }
        }

        /// <summary>
        /// Sync with an IPTables system
        /// </summary>
        /// <param name="canDeleteSet"></param>
        /// <param name="transactional"></param>
        public void Sync(
            Func<IpSetSet, bool> canDeleteSet = null, bool transactional = true)
        {
            if (transactional)
            {
                //Start transaction
                System.SetAdapter.StartTransaction();
            }

            var systemSets = System.SetAdapter.SaveSets(System);

            foreach (var set in _sets.Values)
            {
                var systemSet = systemSets.GetSetByName(set.Name);
                if (systemSet == null)
                {
                    //Add
                    System.SetAdapter.CreateSet(set);
                    systemSet = new IpSetSet(set.Type, set.Name, set.Timeout, "inet", System, set.SyncMode);
                }
                else
                {
                    //Update if applicable
                    if (!systemSet.SetEquals(set))
                    {
                        System.SetAdapter.DestroySet(set.Name);
                        System.SetAdapter.CreateSet(set);
                        systemSet = new IpSetSet(set.Type, set.Name, set.Timeout, "inet", System, set.SyncMode, set.Entries);
                    }
                }

                if (set.SyncMode == IpSetSyncMode.SetAndEntries)
                {
                    HashSet<IpSetEntry> indexedEntries = new HashSet<IpSetEntry>(set.Entries, new IpSetEntryKeyComparer());
                    HashSet<IpSetEntry> systemEntries = new HashSet<IpSetEntry>(systemSet.Entries, new IpSetEntryKeyComparer());
                    try
                    {
                        foreach (var entry in indexedEntries)
                        {
                            if (!systemEntries.Remove(entry))
                            {
                                System.SetAdapter.AddEntry(entry);
                            }
                        }

                        foreach (var entry in systemEntries)
                        {
                            System.SetAdapter.DeleteEntry(entry);
                        }
                    }
                    catch (Exception ex)
                    {
                        throw new IpTablesNetException(String.Format("An exception occured while adding or removing on entries of set {0} message:{1}",set.Name,ex.Message),ex);
                    }
                }
            }

            if (canDeleteSet != null)
            {
                foreach (var set in systemSets.Sets)
                {
                    if (!_sets.ContainsKey(set.Name) && canDeleteSet(set))
                    {
                        System.SetAdapter.DestroySet(set.Name);
                    }
                }
            }

            if (transactional)
            {
                //End Transaction: COMMIT
                if (!System.SetAdapter.EndTransactionCommit())
                {
                    throw new IpTablesNetException("Failed to commit IPSets");
                }
            }
        }

        public IpSetSet GetSetByName(string name)
        {
            IpSetSet ret = null;
            _sets.TryGetValue(name, out ret);
            return ret;
        }

        public void AddSet(IpSetSet set)
        {
            _sets.Add(set.Name, set);
        }

        public void Accept(String line, IpTablesSystem iptables)
        {
            String[] split = ArgumentHelper.SplitArguments(line);

            if (split.Length == 0) return;

            var command = split[0];
            switch (command)
            {
                case "create":
                    var set = IpSetSet.Parse(split, iptables, 1);
                    AddSet(set);
                    break;
                case "add":
                    IpSetEntry.Parse(split, this, 1);
                    break;
            }
        }
    }
}
