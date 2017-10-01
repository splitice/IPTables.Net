using System;
using System.Collections.Generic;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Socket
{
    public class SocketModule : ModuleBase, IEquatable<SocketModule>, IIpTablesModule
    {
        private const String OptionTransparent = "--transparent";

        public bool Transparent;

        public SocketModule(int version) : base(version)
        {
        }

        public bool Equals(SocketModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Transparent.Equals(other.Transparent);
        }

        public int Feed(RuleParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionTransparent:
                    Transparent = true;
                    break;
            }

            return 0;
        }

        public bool NeedsLoading
        {
            get { return true; }
        }

        public String GetRuleString()
        {
            if (Transparent)
            {
                return OptionTransparent;
            }
            return "";
        }

        public static HashSet<String> GetOptions()
        {
            var options = new HashSet<string>
            {
                OptionTransparent
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("socket", typeof(SocketModule), GetOptions);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((SocketModule)obj);
        }

        public override int GetHashCode()
        {
            return Transparent.GetHashCode();
        }
    }
}