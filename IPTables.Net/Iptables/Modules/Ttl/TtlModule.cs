using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Ttl
{
    public class TtlModule : ModuleBase, IIpTablesModule //, IEquatable<TtlModule>
    {
        private const string OptionInc = "--ttl-inc";

        public TtlModule(int version) : base(version)
        {
        }

        public uint Increment { get; set; }

        public bool NeedsLoading => false;

        public int Feed(CommandParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionInc:
                    Increment = uint.Parse(parser.GetNextArg());
                    return 1;
            }

            return 0;
        }

        public string GetRuleString()
        {
            var sb = new StringBuilder();

            if (Increment > 0)
            {
                sb.Append(OptionInc + " ");
                sb.Append(Increment);
            }

            return sb.ToString();
        }

        public static HashSet<string> GetOptions()
        {
            var options = new HashSet<string>
            {
                OptionInc
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetTargetModuleEntryInternal("TTL", typeof(TtlModule), GetOptions, (version) => new TtlModule(version), false);
        }

        protected bool Equals(TtlModule other)
        {
            return Equals(Increment, other.Increment);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((TtlModule) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return Increment.GetHashCode();
            }
        }
    }
}