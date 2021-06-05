using System;
using System.Collections.Generic;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Netflow
{
    public class NetflowMatchModule : ModuleBase, IEquatable<NetflowMatchModule>, IIpTablesModule
    {
        private const string OptionFwStatus = "--fw_status";
        private const string OptionNoPorts = "--nf-noports";

        public int FwStatus;
        public bool NoPorts;

        public NetflowMatchModule(int version) : base(version)
        {
        }

        public bool Equals(NetflowMatchModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return FwStatus.Equals(other.FwStatus) && NoPorts == other.NoPorts;
        }

        public int Feed(CommandParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionFwStatus:
                    FwStatus = int.Parse(parser.GetNextArg());
                    return 1;

                case OptionNoPorts:
                    NoPorts = true;
                    return 0;
            }

            return 0;
        }

        public bool NeedsLoading => true;

        public string GetRuleString()
        {
            var ret = "";
            if (FwStatus != 0) ret = OptionFwStatus + " " + FwStatus;
            if (NoPorts)
            {
                if (ret.Length != 0) ret += " ";
                ret += OptionNoPorts;
            }

            return ret;
        }

        public static HashSet<string> GetOptions()
        {
            var options = new HashSet<string>
            {
                OptionFwStatus,
                OptionNoPorts
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("netflow", typeof(NetflowMatchModule), GetOptions);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((NetflowMatchModule) obj);
        }

        public override int GetHashCode()
        {
            return FwStatus.GetHashCode();
        }
    }
}