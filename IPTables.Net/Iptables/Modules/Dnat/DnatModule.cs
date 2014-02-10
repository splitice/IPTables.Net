using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Dnat
{
    public class DnatModule : ModuleBase, IIptablesModule, IEquatable<DnatModule>
    {
        private const String OptionToDestination = "--to-destination";
        private const String OptionRandom = "--random";
        private const String OptionPersisent = "--persistent";

        public bool Persistent = false;
        public bool Random = false;
        public IPPortOrRange ToDestination = new IPPortOrRange(IPAddress.Any);

        public bool NeedsLoading
        {
            get
            {
                return false;
            }
        }

        public int Feed(RuleParser parser, bool not)
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

        public String GetRuleString()
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

        public static IEnumerable<String> GetOptions()
        {
            var options = new List<string>
                          {
                              OptionToDestination,
                              OptionRandom,
                              OptionPersisent
                          };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetTargetModuleEntryInternal("DNAT", typeof (DnatModule), GetOptions, true);
        }

        public bool Equals(DnatModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Persistent.Equals(other.Persistent) && Random.Equals(other.Random) && ToDestination.Equals(other.ToDestination);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((DnatModule) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hashCode = Persistent.GetHashCode();
                hashCode = (hashCode*397) ^ Random.GetHashCode();
                hashCode = (hashCode*397) ^ ToDestination.GetHashCode();
                return hashCode;
            }
        }
    }
}