using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Ts3Init
{
    public class Ts3InitSetCookieModule : ModuleBase, IIpTablesModule, IEquatable<Ts3InitSetCookieModule>
    {
        private const String OptionRandomSeed = "--random-seed";

        public String RandomSeed;

        public Ts3InitSetCookieModule(int version) : base(version)
        {
        }

        public bool NeedsLoading
        {
            get { return false; }
        }

        public int Feed(CommandParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionRandomSeed:
                    RandomSeed = parser.GetNextArg();
                    return 1;
            }

            return 0;
        }

        public String GetRuleString()
        {
            return OptionRandomSeed + " "+ RandomSeed;
        }

        public static HashSet<String> GetOptions()
        {
            return new HashSet<string>()
            {
                OptionRandomSeed
            };
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetTargetModuleEntryInternal("TS3INIT_SET_COOKIE", typeof (Ts3InitSetCookieModule), GetOptions, false);
        }

        public bool Equals(Ts3InitSetCookieModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return string.Equals(RandomSeed, other.RandomSeed);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((Ts3InitSetCookieModule) obj);
        }

        public override int GetHashCode()
        {
            return (RandomSeed != null ? RandomSeed.GetHashCode() : 0);
        }
    }
}