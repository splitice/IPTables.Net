using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.IpSet.Adapter;

namespace IPTables.Net.Iptables.IpSet
{
    public class IpSetSets
    {
        private List<IpSetSet> _sets = new List<IpSetSet>();
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
            get { return _sets; }
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
                _system.SetAdapter.StartTransaction();
            }

            var systemSets = _system.SetAdapter.SaveSets(_system);

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
                    if (!systemSet.SetEquals(set))
                    {
                        _system.SetAdapter.DestroySet(set.Name);
                        _system.SetAdapter.CreateSet(set);
                        systemSet = new IpSetSet(set.Type, set.Name, set.Timeout, _system, set.SyncMode);
                    }
                }

                if (set.SyncMode == IpSetSyncMode.SetAndEntries)
                {
                    try
                    {
                        foreach (var entry in set.Entries)
                        {
                            try
                            {
                                var systemEntry = systemSet.Entries.FirstOrDefault((a) => a.KeyEquals(entry));
                                if (systemEntry == null)
                                {
                                    _system.SetAdapter.AddEntry(entry);
                                }
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine(entry.Port);
                                Console.WriteLine(systemSet.Entries.Count);
                                throw;
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
                    if (_sets.FirstOrDefault((a) => a.Name == set.Name) == null && canDeleteSet(set))
                    {
                        _system.SetAdapter.DestroySet(set.Name);
                    }
                }
            }

            if (transactional)
            {
                //End Transaction: COMMIT
                _system.SetAdapter.EndTransactionCommit();
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
