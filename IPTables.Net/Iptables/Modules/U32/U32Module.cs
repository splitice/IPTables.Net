using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Iptables.Helpers;
using IPTables.Net.Iptables.U32;

namespace IPTables.Net.Iptables.Modules.U32
{
    public class U32Module : ModuleBase, IEquatable<U32Module>, IIpTablesModule
    {
        private const string OptionBytecode = "--u32";

        public U32Expression ByteCode;

        public U32Module(int version) : base(version)
        {
        }

        public bool Equals(U32Module other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return ByteCode.Equals(other.ByteCode);
        }

        public int Feed(CommandParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionBytecode:
                    ByteCode = U32Expression.Parse(parser.GetNextArg());
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
                sb.Append("--u32 ");
                sb.Append(ShellHelper.EscapeArguments(ByteCode.ToString()));
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
            return GetModuleEntryInternal("u32", typeof(U32Module), GetOptions);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((U32Module) obj);
        }

        public override int GetHashCode()
        {
            return ByteCode != null ? ByteCode.GetHashCode() : 0;
        }
    }
}