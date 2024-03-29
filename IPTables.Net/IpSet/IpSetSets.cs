﻿using System;
using System.Collections.Generic;
using IPTables.Net.Exceptions;
using IPTables.Net.Supporting;

namespace IPTables.Net.IpSet
{
    public class IpSetSets
    {
        private Dictionary<string, IpSetSet> _sets = new Dictionary<string, IpSetSet>();
        private IpTablesSystem _system;

        public IpSetSets(IEnumerable<string> commands, IpTablesSystem system)
        {
            _system = system;
            foreach (var command in commands) Accept(command, system);
        }

        public IpSetSets(IpTablesSystem system)
        {
            _system = system;
        }

        public IEnumerable<IpSetSet> Sets => _sets.Values;

        public IpTablesSystem System => _system;

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
                //Start transaction
                System.SetAdapter.StartTransaction();

            // Dump sets in system
            var systemSets = System.SetAdapter.SaveSets(System);

            // Check sets for need to change and install entries
            foreach (var set in _sets.Values)
            {
                var created = false;
                var systemSet = systemSets.GetSetByName(set.Name);
                if (systemSet == null)
                {
                    //Add
                    System.SetAdapter.CreateSet(set);
                    systemSet = new IpSetSet(set.Type, set.Name, set.Timeout, set.Family, System, set.SyncMode,
                        set.BitmapRange, set.CreateOptions) {HashSize = set.HashSize, MaxElem = set.MaxElem};
                    created = true;
                }
                else
                {
                    //Update if applicable
                    if (!systemSet.SetEquals(set))
                    {
                        // Create a new set as _S of the target
                        systemSet = new IpSetSet(set.Type, set.Name + "_S", set.Timeout, set.Family, System,
                            set.SyncMode, set.BitmapRange, set.CreateOptions);
                        systemSet.HashSize = set.HashSize;
                        systemSet.MaxElem = set.MaxElem;
                        System.SetAdapter.CreateSet(systemSet);

                        // Swap (setname becomes setname+"_S" but keeps it's items)
                        System.SetAdapter.SwapSet(systemSet.Name, set.Name);
                        System.SetAdapter.DestroySet(systemSet.Name);
                        systemSet.InternalName = set.Name;

                        // We created something new
                        created = true;
                    }
                }

                if (set.SyncMode == IpSetSyncMode.SetAndEntries ||
                    set.SyncMode == IpSetSyncMode.SetAndEntriesOnCreate && created)
                    systemSet.SyncEntries(set);
            }

            // Do set deletions
            if (canDeleteSet != null)
                foreach (var set in systemSets.Sets)
                    if (!_sets.ContainsKey(set.Name) && canDeleteSet(set))
                        System.SetAdapter.DestroySet(set.Name);

            // End of transaction
            if (transactional)
                //End Transaction: COMMIT
                if (!System.SetAdapter.EndTransactionCommit())
                    throw new IpTablesNetException("Failed to commit IPSets");
        }


        public IpSetSet GetSetByName(string name, bool fromSystem = false)
        {
            if (fromSystem) LoadFromSystem(name);

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
            if (force)
                _sets[set.Name] = set;
            else
                _sets.Add(set.Name, set);
        }

        public void Accept(string line, IpTablesSystem iptables)
        {
            var split = ArgumentHelper.SplitArguments(line);

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