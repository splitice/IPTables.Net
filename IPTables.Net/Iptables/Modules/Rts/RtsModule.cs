using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Rts
{
    public class RtsModule : ModuleBase, IIpTablesModule //, IEquatable<RtsModule>
    {
        private const string OptionDst = "--rts-dst";

        public IPAddress Dst;


        public RtsModule(int version) : base(version)
        {
            if (version == 4)
                Dst = IPAddress.Any;
            else
                Dst = IPAddress.IPv6Any;
        }

        public bool NeedsLoading => false;

        public int Feed(CommandParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionDst:
                    Dst = IPAddress.Parse(parser.GetNextArg());
                    return 1;
            }

            return 0;
        }

        public string GetRuleString()
        {
            var sb = new StringBuilder();

            if (!Equals(Dst, IPAddress.Any) && !Equals(Dst, IPAddress.IPv6Any))
            {
                sb.Append(OptionDst + " ");
                sb.Append(Dst);
            }

            return sb.ToString();
        }

        public static HashSet<string> GetOptions()
        {
            var options = new HashSet<string>
            {
                OptionDst
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetTargetModuleEntryInternal("RTS", typeof(RtsModule), GetOptions, (version) => new RtsModule(version), false);
        }

        protected bool Equals(RtsModule other)
        {
            return Equals(Dst, other.Dst);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((RtsModule) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return Dst != null ? Dst.GetHashCode() : 0;
            }
        }
    }
}