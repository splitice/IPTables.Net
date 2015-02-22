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
            _system.TableAdapter.StartTransaction();

            var systemSets = _system.SetAdapter.GetSets();

            var tableChains = new Dictionary<string, List<IpTablesChain>>();
            /*foreach (IpSetSet set in Sets)
            {
                if (!tableChains.ContainsKey(chain.Table))
                {
                    var chains = _system.GetChains(chain.Table).ToList();
                    tableChains.Add(chain.Table, chains);
                }
                if (tableChains[chain.Table].FirstOrDefault(a => a.Name == chain.Name && a.Table == chain.Table) == null)
                {
                    //Chain doesnt exist create
                    tableChains[chain.Table].Add(_system.AddChain(chain));
                }
            }

            foreach (IpSetSet set in Sets)
            {
                IpTablesChain realChain =
                    tableChains[chain.Table].First(a => a.Name == chain.Name && a.Table == chain.Table);
                if (realChain != null)
                {
                    //Update chain
                    realChain.SyncInternal(chain.Rules, sync);
                }
            }*/

            if (canDeleteSet != null)
            {
                foreach (var set in systemSets)
                {
                    if (_sets.FirstOrDefault((a) => a.Name == set.Name) == null && canDeleteSet(set))
                    {
                        set.DeleteSet();
                    }
                }
            }

            //End Transaction: COMMIT
            _system.TableAdapter.EndTransactionCommit();
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
