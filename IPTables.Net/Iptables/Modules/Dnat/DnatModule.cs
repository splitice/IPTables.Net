using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Dnat
{
    public class DnatModule : ModuleBase, IIpTablesModule, IEquatable<DnatModule>
    {
        private const string OptionToDestination = "--to-destination";
        private const string OptionRandom = "--random";
        private const string OptionPersisent = "--persistent";

        public bool Persistent { get; set; } = false;
        public bool Random { get; set; } = false;
        public IPPortOrRange ToDestination { get; set; } = new IPPortOrRange(IPAddress.Any);

        public DnatModule(int version) : base(version)
        {
        }

        public bool Equals(DnatModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Persistent.Equals(other.Persistent) && Random.Equals(other.Random) &&
                   ToDestination.Equals(other.ToDestination);
        }

        public bool NeedsLoading => false;

        public int Feed(CommandParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionToDestination:
                    ToDestination = IPPortOrRange.Parse(parser.GetNextArg());
                    return 1;

                case OptionRandom:
                    Random = true;
                    return 0;

                case OptionPersisent:
                    Persistent = true;
                    return 0;
            }

            return 0;
        }

        public string GetRuleString()
        {
            var sb = new StringBuilder();

            if (!Equals(ToDestination.LowerAddress, IPAddress.Any))
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(OptionToDestination + " ");
                sb.Append(ToDestination);
            }

            if (Random)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(OptionRandom);
            }

            if (Persistent)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(OptionPersisent);
            }

            return sb.ToString();
        }

        public static HashSet<string> GetOptions()
        {
            var options = new HashSet<string>
            {
                OptionToDestination,
                OptionRandom,
                OptionPersisent
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetTargetModuleEntryInternal("DNAT", typeof(DnatModule), GetOptions, false);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((DnatModule) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = Persistent.GetHashCode();
                hashCode = (hashCode * 397) ^ Random.GetHashCode();
                hashCode = (hashCode * 397) ^ ToDestination.GetHashCode();
                return hashCode;
            }
        }
    }
}