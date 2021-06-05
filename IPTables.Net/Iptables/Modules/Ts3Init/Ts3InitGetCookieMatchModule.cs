using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Ts3Init
{
    public class Ts3InitGetCookieMatchModule : ModuleBase, IIpTablesModule, IEquatable<Ts3InitGetCookieMatchModule>
    {
        private const string OptionCheckTime = "--check-time";
        private const string OptionMinClient = "--min-client";

        public ulong MinClient;
        public uint? CheckTime;

        public Ts3InitGetCookieMatchModule(int version) : base(version)
        {
        }

        public bool NeedsLoading => true;

        public int Feed(CommandParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionMinClient:
                    MinClient = ulong.Parse(parser.GetNextArg());
                    return 1;
                case OptionCheckTime:
                    CheckTime = uint.Parse(parser.GetNextArg());
                    return 1;
            }

            return 0;
        }

        public string GetRuleString()
        {
            var sb = new StringBuilder();
            if (MinClient > 0) sb.Append(OptionMinClient + " " + MinClient);

            if (CheckTime.HasValue)
            {
                if (sb.Length != 0) sb.Append(" ");
                sb.Append(OptionCheckTime + " " + CheckTime.Value);
            }

            return sb.ToString();
        }

        public static HashSet<string> GetOptions()
        {
            return new HashSet<string>()
            {
                OptionCheckTime,
                OptionMinClient
            };
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("ts3init_get_cookie", typeof(Ts3InitGetCookieMatchModule), GetOptions);
        }

        public bool Equals(Ts3InitGetCookieMatchModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return MinClient == other.MinClient && CheckTime == other.CheckTime;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((Ts3InitGetCookieMatchModule) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return (MinClient.GetHashCode() * 397) ^ (int) CheckTime;
            }
        }
    }
}