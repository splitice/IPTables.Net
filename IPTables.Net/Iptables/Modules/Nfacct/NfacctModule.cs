using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Iptables.Helpers;
using IPTables.Net.Supporting;

namespace IPTables.Net.Iptables.Modules.Nfacct
{
    public class NfacctModule : ModuleBase, IEquatable<NfacctModule>, IIpTablesModule
    {
        private const string OptionNameLong = "--nfacct-name";

        public string Name;

        public NfacctModule(int version) : base(version)
        {
        }

        public bool Equals(NfacctModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return string.Equals(Name, other.Name);
        }

        public int Feed(CommandParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionNameLong:
                    Name = parser.GetNextArg();
                    return 1;
            }

            return 0;
        }

        public bool NeedsLoading => true;

        public string GetRuleString()
        {
            var sb = new StringBuilder();

            if (!string.IsNullOrEmpty(Name))
            {
                sb.Append("--nfacct-name ");
                sb.Append(ShellHelper.EscapeArguments(Name));
            }

            return sb.ToString();
        }

        public static HashSet<string> GetOptions()
        {
            var options = new HashSet<string>
            {
                OptionNameLong
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("nfacct", typeof(NfacctModule), GetOptions);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((NfacctModule) obj);
        }

        public override int GetHashCode()
        {
            return Name != null ? Name.GetHashCode() : 0;
        }
    }
}