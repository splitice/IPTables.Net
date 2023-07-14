using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Dynjmp
{
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors | DynamicallyAccessedMemberTypes.PublicMethods | DynamicallyAccessedMemberTypes.PublicProperties | DynamicallyAccessedMemberTypes.NonPublicFields)]
    public class DynjmpModule : ModuleBase, IIpTablesModule, IEquatable<DynjmpModule>
    {
        public DynjmpModule(int version) : base(version)
        {
        }

        public bool Equals(DynjmpModule other)
        {
            if (ReferenceEquals(null, other)) return false;
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
            return new HashSet<string>();
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetTargetModuleEntryInternal("DYNJMP", typeof(DynjmpModule), GetOptions, (version) => new DynjmpModule(version), false);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((DynjmpModule) obj);
        }

        public override int GetHashCode()
        {
            return 133;
        }
    }
}