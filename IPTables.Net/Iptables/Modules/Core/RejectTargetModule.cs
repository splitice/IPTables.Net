using System;
using System.Collections.Generic;
using System.Text;

namespace IPTables.Net.Iptables.Modules.Core
{
    internal class RejectTargetModule : ModuleBase, IIpTablesModule, IEquatable<RejectTargetModule>
    {
        private const string OptionRejectWith = "--reject-with";

        public string RejectWith { get; set; } = "";

        public RejectTargetModule(int version) : base(version)
        {
        }

        public bool Equals(RejectTargetModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return string.Equals(RejectWith, other.RejectWith);
        }

        public bool NeedsLoading => false;

        public int Feed(CommandParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionRejectWith:
                    RejectWith = parser.GetNextArg();
                    return 1;
            }

            return 0;
        }

        public string GetRuleString()
        {
            var sb = new StringBuilder();

            if (!string.IsNullOrEmpty(RejectWith))
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(OptionRejectWith + " ");
                sb.Append(RejectWith);
            }

            return sb.ToString();
        }

        public static HashSet<string> GetOptions()
        {
            var options = new HashSet<string>
            {
                OptionRejectWith
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetTargetModuleEntryInternal("REJECT", typeof(RejectTargetModule), GetOptions, (version) => new RejectTargetModule(version), true);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((RejectTargetModule) obj);
        }

        public override int GetHashCode()
        {
            return RejectWith != null ? RejectWith.GetHashCode() : 0;
        }
    }
}