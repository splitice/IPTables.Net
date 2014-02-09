using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using IPTables.Net.Iptables.DataTypes;
using IPTables.Net.Iptables.Modules.Base;

namespace IPTables.Net.Iptables.Modules
{
    public class Snat : ModuleBase, IIptablesModule, IEquatable<Snat>
    {
        private const String OptionToSource = "--to-source";
        private const String OptionRandom = "--random";
        private const String OptionPersisent = "--persistent";

        public bool Persistent = false;
        public bool Random = false;
        public IPPortOrRange ToSource = new IPPortOrRange(IPAddress.Any);

        public int Feed(RuleParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionToSource:
                    ToSource = IPPortOrRange.Parse(parser.GetNextArg());
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

            if (Equals(ToSource.LowerAddress, IPAddress.Any))
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(OptionToSource + " ");
                sb.Append(ToSource);
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
                              OptionToSource,
                              OptionRandom,
                              OptionPersisent
                          };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("snat", typeof (Snat), GetOptions, true);
        }

        public bool Equals(Snat other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Persistent.Equals(other.Persistent) && Random.Equals(other.Random) && ToSource.Equals(other.ToSource);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((Snat) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hashCode = Persistent.GetHashCode();
                hashCode = (hashCode*397) ^ Random.GetHashCode();
                hashCode = (hashCode*397) ^ ToSource.GetHashCode();
                return hashCode;
            }
        }
    }
}