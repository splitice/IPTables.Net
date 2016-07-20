using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Iptables.Helpers;

namespace IPTables.Net.Iptables.Modules.BpfL4
{
    public class BpfL4Module : ModuleBase, IEquatable<BpfL4Module>, IIpTablesModule
    {
        private const String OptionBytecode = "--bytecodel4";

        public String ByteCode;

        public BpfL4Module(int version) : base(version)
        {
        }

        public bool Equals(BpfL4Module other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return string.Equals(ByteCode, other.ByteCode);
        }

        public int Feed(RuleParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionBytecode:
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
                sb.Append("--bytecodel4 ");
                sb.Append(ShellHelper.EscapeArguments(ByteCode));
            }

            return sb.ToString();
        }

        public static HashSet<String> GetOptions()
        {
            var options = new HashSet<string>
            {
                OptionBytecode
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("bpfl4", typeof(BpfL4Module), GetOptions);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((BpfL4Module)obj);
        }

        public override int GetHashCode()
        {
            return (ByteCode != null ? ByteCode.GetHashCode() : 0);
        }
    }
}