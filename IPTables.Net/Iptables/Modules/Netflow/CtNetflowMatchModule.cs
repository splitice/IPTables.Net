using System;
using System.Collections.Generic;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Netflow
{
    public class CtNetflowMatchModule : ModuleBase, IEquatable<CtNetflowMatchModule>, IIpTablesModule
    {
        private const string OptionFwStatus = "--fw_status";

        public int FwStatus;

        public CtNetflowMatchModule(int version) : base(version)
        {
        }

        public bool Equals(CtNetflowMatchModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return FwStatus.Equals(other.FwStatus);
        }

        public int Feed(CommandParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionFwStatus:
                    FwStatus = int.Parse(parser.GetNextArg());
                    return 1;
            }

            return 0;
        }

        public bool NeedsLoading => true;

        public string GetRuleString()
        {
            if (FwStatus != 0) return OptionFwStatus + " " + FwStatus;
            return "";
        }

        public static HashSet<string> GetOptions()
        {
            var options = new HashSet<string>
            {
                OptionFwStatus
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("ctnetflow", typeof(CtNetflowMatchModule), GetOptions, (version) => new CtNetflowMatchModule(version));
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((CtNetflowMatchModule) obj);
        }

        public override int GetHashCode()
        {
            return FwStatus.GetHashCode();
        }
    }
}