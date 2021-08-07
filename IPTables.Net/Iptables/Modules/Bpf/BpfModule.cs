using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Iptables.Helpers;
using IPTables.Net.Supporting;

namespace IPTables.Net.Iptables.Modules.Bpf
{
    public class BpfModule : ModuleBase, IEquatable<BpfModule>, IIpTablesModule
    {
        private const string OptionBytecode = "--bytecode";

        public string ByteCode { get; set; }

        public BpfModule(int version) : base(version)
        {
        }

        public bool Equals(BpfModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return string.Equals(ByteCode, other.ByteCode);
        }

        public int Feed(CommandParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionBytecode:
                    ByteCode = parser.GetNextArg();
                    return 1;
            }

            return 0;
        }

        public bool NeedsLoading => true;

        public string GetRuleString()
        {
            var sb = new StringBuilder();

            if (ByteCode != null)
            {
                sb.Append("--bytecode ");
                sb.Append(ShellHelper.EscapeArguments(ByteCode));
            }

            return sb.ToString();
        }

        public static HashSet<string> GetOptions()
        {
            var options = new HashSet<string>
            {
                OptionBytecode
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
            return Equals((BpfModule) obj);
        }

        public override int GetHashCode()
        {
            return ByteCode != null ? ByteCode.GetHashCode() : 0;
        }
    }
}