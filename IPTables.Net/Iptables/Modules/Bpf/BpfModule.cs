using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Iptables.Helpers;

namespace IPTables.Net.Iptables.Modules.Bpf
{
    public class BpfModule : ModuleBase, IEquatable<BpfModule>, IIpTablesModuleGod
    {
        private const String OptionCommentLong = "--bytecode";

        public String ByteCode;

        public bool Equals(BpfModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return string.Equals(ByteCode, other.ByteCode);
        }

        int IIpTablesModuleInternal.Feed(RuleParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionCommentLong:
                    ByteCode = parser.GetNextArg();
                    return 1;
            }

            return 0;
        }

        public bool NeedsLoading
        {
            get { return true; }
        }

        public String GetRuleString()
        {
            var sb = new StringBuilder();

            if (ByteCode != null)
            {
                sb.Append("--bytecode ");
                sb.Append(ShellHelper.EscapeArguments(ByteCode));
            }

            return sb.ToString();
        }

        public static IEnumerable<String> GetOptions()
        {
            var options = new List<string>
            {
                OptionCommentLong
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("bpf", typeof(BpfModule), GetOptions);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((BpfModule)obj);
        }

        public override int GetHashCode()
        {
            return (ByteCode != null ? ByteCode.GetHashCode() : 0);
        }
    }
}