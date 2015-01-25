using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using SystemInteract;
using IPTables.Net.Netfilter;

namespace IPTables.Net.Iptables.IpSet.Adapter
{
    class IpSetBinaryAdapter
    {
        private const String BinaryName = "ipset";

        private readonly NetfilterSystem _system;

        public IpSetBinaryAdapter(NetfilterSystem system)
        {
            _system = system;
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

        public List<bool> SaveSets()
        {
            ISystemProcess process = _system.System.StartProcess(BinaryName, "save");

            Dictionary<String, IpSetSet> sets = new Dictionary<string, IpSetSet>();

            return null;
        }

        public void DestroySet(String name)
        {
            String command = String.Format("destroy {0}", name);
        }
    }
}
