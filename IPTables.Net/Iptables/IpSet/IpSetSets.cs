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
            // Start of transaction
            if (transactional)
            {
                //Start transaction
                System.SetAdapter.StartTransaction();
            }

            // Dump sets in system
            var systemSets = System.SetAdapter.SaveSets(System);

            // Check sets for need to change and install entries
            foreach (var set in _sets.Values)
            {
                bool created = false;
                var systemSet = systemSets.GetSetByName(set.Name);
                if (systemSet == null)
                {
                    //Add
                    System.SetAdapter.CreateSet(set);
                    systemSet = new IpSetSet(set.Type, set.Name, set.Timeout, set.Family, System, set.SyncMode, set.BitmapRange, set.CreateOptions);
                    systemSet.HashSize = set.HashSize;
                    systemSet.MaxElem = set.MaxElem;
                    created = true;
                }
                else
                {
                    //Update if applicable
                    if (!systemSet.SetEquals(set))
                    {
                        // Create a new set as _S of the target
                        systemSet = new IpSetSet(set.Type, set.Name + "_S", set.Timeout, set.Family, System, set.SyncMode, set.BitmapRange, set.CreateOptions, set.Entries);
                        systemSet.HashSize = set.HashSize;
                        systemSet.MaxElem = set.MaxElem;
                        System.SetAdapter.CreateSet(systemSet);
                        
                        // Swap then destroy
                        System.SetAdapter.SwapSet(systemSet.Name, set.Name);
                        System.SetAdapter.DestroySet(systemSet.Name);
                        systemSet.InternalName = set.Name;

                        // We created something new
                        created = true;
                    }
                }

                if (set.SyncMode == IpSetSyncMode.SetAndEntries || 
                    (set.SyncMode == IpSetSyncMode.SetAndEntriesOnCreate && created))
                {
                    set.SyncEntries(systemSet);
                }
            }

            // Do set deletions
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

            // End of transaction
            if (transactional)
            {
                //End Transaction: COMMIT
                if (!System.SetAdapter.EndTransactionCommit())
                {
                    throw new IpTablesNetException("Failed to commit IPSets");
                }
            }
        }


        public IpSetSet GetSetByName(string name, bool fromSystem = false)
        {
            if (fromSystem)
            {
                LoadFromSystem(name);
            }

            IpSetSet ret = null;
            _sets.TryGetValue(name, out ret);
            return ret;
        }

        private void LoadFromSystem(string name = null)
        {
            System.SetAdapter.SaveSets(this, name);
        }

        public bool HasSet(string name)
        {
            return _sets.ContainsKey(name);
        }

        public void AddSet(IpSetSet set, bool force = false)
        {
            if (force && _sets.ContainsKey(set.Name))
            {
                _sets[set.Name] = set;
            }
            else
            {
                _sets.Add(set.Name, set);
            }
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
                    AddSet(set, true);
                    break;
                case "add":
                    IpSetEntry.Parse(split, this, 1);
                    break;
            }
        }
    }
}
