using System;
using System.Collections.Generic;

namespace IPTables.Net.Iptables.Modules.Netflow
{
    public class NetflowModule : ModuleBase, IIpTablesModule, IEquatable<NetflowModule>
    {
        public NetflowModule(int version) : base(version)
        {
        }

        public bool Equals(NetflowModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return true;
        }

        public bool NeedsLoading => false;

        public int Feed(CommandParser parser, bool not)
        {
            return 0;
        }

        public string GetRuleString()
        {
            return "";
        }

        public static HashSet<string> GetOptions()
        {
            var options = new HashSet<string>
            {
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetTargetModuleEntryInternal("NETFLOW", typeof(NetflowModule), GetOptions, (version) => new NetflowModule(version), true);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((NetflowModule) obj);
        }
    }
}