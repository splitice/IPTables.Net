using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Ts3Init
{
    public class Ts3InitReset : ModuleBase, IIpTablesModule, IEquatable<Ts3InitReset>
    {
        public Ts3InitReset(int version) : base(version)
        {
        }

        public bool Equals(Ts3InitReset other)
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
            return GetTargetModuleEntryInternal("TS3INIT_RESET", typeof(Ts3InitGetCookieModule), GetOptions, false);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((Ts3InitReset) obj);
        }

        public override int GetHashCode()
        {
            return 134;
        }
    }
}