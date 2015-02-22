using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using IPTables.Net.Iptables.IpSet.Sync;

namespace IPTables.Net.Iptables.IpSet
{
    public class IpSetSets
    {
        private List<IpSetSet> _sets = new List<IpSetSet>();
        private IpTablesSystem _system;

        public IpSetSets(IpTablesSystem system)
        {
            _system = system;
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
        public void Sync(IIPSetSync sync,
            Func<IpSetSet, bool> canDeleteSet = null)
        {
            //Start transaction
            _system.SetAdapter.StartTransaction();

            var systemSets = _system.SetAdapter.SaveSets();

            foreach (var set in _sets)
            {
                var systemSet = systemSets.GetSetByName(set.Name);
                if (systemSet == null)
                {
                    //Add
                    _system.SetAdapter.CreateSet(set);
                    systemSet = new IpSetSet(set.Type, set.Name, set.Timeout, _system, set.SyncMode);
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
                            _system.SetAdapter.AddEntry(entry);
                        }
                    }

                    foreach (var entry in systemSet.Entries)
                    {
                        IpSetEntry entry1 = entry;
                        var memEntry = set.Entries.FirstOrDefault(((a) => a.KeyEquals(entry1)));
                        if (memEntry == null)
                        {
                            _system.SetAdapter.DeleteEntry(entry);
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
                        _system.SetAdapter.DestroySet(set.Name);
                    }
                }
            }

            //End Transaction: COMMIT
            _system.SetAdapter.EndTransactionCommit();
        }

        public IpSetSet GetSetByName(string name)
        {
            return Sets.FirstOrDefault((a) => a.Name == name);
        }

        public void AddSet(IpSetSet set)
        {
            _sets.Add(set);
        }
    }
}
