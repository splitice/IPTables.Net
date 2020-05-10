using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Ts3Init
{
    public class Ts3InitGetPuzzleModule : ModuleBase, IIpTablesModule, IEquatable<Ts3InitGetPuzzleModule>
    {
        private const String OptionRandomSeed = "--random-seed";
        private const String OptionMinClient = "--min-client";
        private const String OptionCheckCookie = "--check-cookie";

        public String RandomSeed;
        public UInt64 MinClient;
        public bool CheckCookie;

        public Ts3InitGetPuzzleModule(int version) : base(version)
        {
        }

        public bool NeedsLoading
        {
            get { return true; }
        }

        public int Feed(CommandParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionRandomSeed:
                    RandomSeed = parser.GetNextArg();
                    return 1;
                case OptionMinClient:
                    MinClient = UInt64.Parse(parser.GetNextArg());
                    return 1;
                case OptionCheckCookie:
                    CheckCookie = true;
                    return 0;
            }

            return 0;
        }

        public String GetRuleString()
        {
            var sb = new StringBuilder(OptionRandomSeed + " " + RandomSeed);
            if (MinClient > 0)
            {
                sb.Append(" " + OptionMinClient + " " + MinClient);
            }
            if (CheckCookie)
            {
                sb.Append(" " + OptionCheckCookie);
            }

            return sb.ToString();
        }

        public static HashSet<String> GetOptions()
        {
            return new HashSet<string>()
            {
                OptionRandomSeed,
                OptionMinClient,
                OptionCheckCookie
            };
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("ts3init_get_puzzle", typeof (Ts3InitGetPuzzleModule), GetOptions);
        }

        public bool Equals(Ts3InitGetPuzzleModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return string.Equals(RandomSeed, other.RandomSeed) && MinClient == other.MinClient && CheckCookie == other.CheckCookie;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((Ts3InitGetPuzzleModule) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = (RandomSeed != null ? RandomSeed.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ MinClient.GetHashCode();
                hashCode = (hashCode * 397) ^ CheckCookie.GetHashCode();
                return hashCode;
            }
        }
    }
}