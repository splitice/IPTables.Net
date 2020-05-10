using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Ts3Init
{
    public class Ts3InitGetCookieMatchModule : ModuleBase, IIpTablesModule, IEquatable<Ts3InitGetCookieMatchModule>
    {
        private const String OptionCheckTime = "--check-time";
        private const String OptionMinClient = "--min-client";
        
        public UInt64 MinClient;
        public UInt32? CheckTime;

        public Ts3InitGetCookieMatchModule(int version) : base(version)
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
                case OptionMinClient:
                    MinClient = UInt64.Parse(parser.GetNextArg());
                    return 1;
                case OptionCheckTime:
                    CheckTime = UInt32.Parse(parser.GetNextArg());
                    return 1;
            }

            return 0;
        }

        public String GetRuleString()
        {
            var sb = new StringBuilder();
            if (MinClient > 0)
            {
                sb.Append(OptionMinClient + " " + MinClient);
            }

            if (CheckTime.HasValue)
            {
                if (sb.Length != 0) sb.Append(" ");
                sb.Append(OptionCheckTime + " " + CheckTime.Value);
            }
            return sb.ToString();
        }

        public static HashSet<String> GetOptions()
        {
            return new HashSet<string>()
            {
                OptionCheckTime,
                OptionMinClient
            };
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("ts3init_get_cookie", typeof (Ts3InitGetCookieMatchModule), GetOptions);
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
            if (obj.GetType() != this.GetType()) return false;
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