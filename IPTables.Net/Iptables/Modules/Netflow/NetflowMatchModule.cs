using System;
using System.Collections.Generic;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Netflow
{
    public class NetflowMatchModule : ModuleBase, IEquatable<NetflowMatchModule>, IIpTablesModule
    {
        private const String OptionFwStatus = "--fw_status";

        public int FwStatus;

        public NetflowMatchModule(int version) : base(version)
        {
        }

        public bool Equals(NetflowMatchModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return FwStatus.Equals(other.FwStatus);
        }

        public int Feed(RuleParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionFwStatus:
                    FwStatus = int.Parse(parser.GetNextArg());
                    return 1;
            }

            return 0;
        }

        public bool NeedsLoading
        {
            get { return true; }
        }

        public String GetRuleString()
        {
            if (FwStatus != 0)
            {
                return OptionFwStatus + " " + FwStatus;
            }
            return "";
        }

        public static HashSet<String> GetOptions()
        {
            var options = new HashSet<string>
            {
                OptionFwStatus
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
            return Equals((NetflowMatchModule)obj);
        }

        public override int GetHashCode()
        {
            return FwStatus.GetHashCode();
        }
    }
}