using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using IPTables.Net.Iptables.IpSet.Adapter;
using IPTables.Net.Iptables.IpSet.Sync;

namespace IPTables.Net.Iptables.IpSet
{
    public class IpSetSets
    {
        private List<IpSetSet> _sets = new List<IpSetSet>();
        private IpSetBinaryAdapter _adapter;

        public IpSetSets(IEnumerable<String> commands, IpTablesSystem system)
        {
            _adapter = system.SetAdapter;
            foreach (var command in commands)
            {
                Accept(command, system);
            }
        }

        public IpSetSets(IpSetBinaryAdapter adapter)
        {
            _adapter = adapter;
        }

        public IEnumerable<IpSetSet> Sets
        {
            get { return _sets; }
        }

        /// <summary>
        /// Sync with an IPTables system
        /// </summary>
        /// <param name="sync"></param>
        /// <param name="canDeleteSet"></param>
        public void Sync(IpTablesSystem system, IIPSetSync sync,
            Func<IpSetSet, bool> canDeleteSet = null, bool transactional = true)
        {
            if (transactional)
            {
                //Start transaction
                _adapter.StartTransaction();
            }

            var systemSets = _adapter.SaveSets(system);

            foreach (var set in _sets)
            {
                var systemSet = systemSets.GetSetByName(set.Name);
                if (systemSet == null)
                {
                    //Add
                    _adapter.CreateSet(set);
                    systemSet = new IpSetSet(set.Type, set.Name, set.Timeout, system, set.SyncMode);
                }
                else
                {
                    //Update if applicable
                    //TODO: update
                }

                if (set.SyncMode == IpSetSyncMode.SetAndEntries)
                {
                    foreach (var entry in set.Entries)
                    {
                        var systemEntry = systemSet.Entries.FirstOrDefault((a) => a.KeyEquals(entry));
                        if (systemEntry == null)
                        {
                            _adapter.AddEntry(entry);
                        }
                    }

                    foreach (var entry in systemSet.Entries)
                    {
                        IpSetEntry entry1 = entry;
                        var memEntry = set.Entries.FirstOrDefault(((a) => a.KeyEquals(entry1)));
                        if (memEntry == null)
                        {
                            _adapter.DeleteEntry(entry);
                        }
                    }
                }
            }

            if (canDeleteSet != null)
            {
                foreach (var set in systemSets.Sets)
                {
                    if (_sets.FirstOrDefault((a) => a.Name == set.Name) == null && canDeleteSet(set))
                    {
                        _adapter.DestroySet(set.Name);
                    }
                }
            }

            if (transactional)
            {
                //End Transaction: COMMIT
                _adapter.EndTransactionCommit();
            }
        }

        public IpSetSet GetSetByName(string name)
        {
            return Sets.FirstOrDefault((a) => a.Name == name);
        }

        public void AddSet(IpSetSet set)
        {
            _sets.Add(set);
        }

        public void Accept(String line, IpTablesSystem iptables)
        {
            String[] split = line.Split(new char[] { ' ' });

            if (split.Length == 0)
            {
                return;
            }

            var command = split[0];
            var options = String.Join(" ", split.Skip(1).ToArray());

            switch (command)
            {
                case "create":
                    var set = IpSetSet.Parse(options, iptables);
                    AddSet(set);
                    break;
                case "add":
                    IpSetEntry.Parse(options, this);
                    break;
            }
        }
    }
}
