using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Dynjmp
{
    public class SynjmpModule : ModuleBase, IIpTablesModule, IEquatable<SynjmpModule>
    {
        public SynjmpModule(int version) : base(version)
        {
        }

        public bool Equals(SynjmpModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            return true;
        }

        public bool NeedsLoading
        {
            get { return false; }
        }

        public int Feed(CommandParser parser, bool not)
        {
            return 0;
        }

        public String GetRuleString()
        {
            return "";
        }

        public static HashSet<String> GetOptions()
        {
            return new HashSet<string>();
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetTargetModuleEntryInternal("SYNJMP", typeof (SynjmpModule), GetOptions, false);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((SynjmpModule) obj);
        }

        public override int GetHashCode()
        {
            return 133;
        }
    }
}