using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Iptables.Modules.Polyfill
{
    public class PolyfillModule : ModuleBase, IIpTablesModuleGod, IEquatable<PolyfillModule>
    {
        private Dictionary<String, List<String>> _data = new Dictionary<String, List<String>>();

        public bool NeedsLoading
        {
            get
            {
                return true;
            }
        }

        int IIpTablesModuleInternal.Feed(RuleParser parser, bool not)
        {
            String current = parser.GetCurrentArg();
            _data.Add(current, new List<string>());
            for (var i = 1; i < parser.GetRemainingArgs(); i++)
            {
                var arg = parser.GetNextArg();
                if (arg[0] == '-')
                {
                    return i;
                }
                _data[current].Add(arg);
            }
            return 0;
        }

        public String GetRuleString()
        {
            var sb = new StringBuilder();

            foreach (var pair in _data)
            {
                sb.Append(pair.Key);
                sb.Append(" ");
                foreach (var a in pair.Value)
                {
                    sb.Append(a);
                    sb.Append(" ");
                }
            }

            return sb.ToString().TrimEnd(new char[]{ ' ' });
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetPolyModuleEntryInternal(typeof (PolyfillModule));
        }

        private static ModuleEntry GetPolyModuleEntryInternal(Type moduleType)
        {
            var entry = new ModuleEntry
            {
                Name = "_",
                Module = moduleType,
                Polyfill = true
            };
            return entry;
        }

        public bool Equals(PolyfillModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return _data.SequenceEqual(other._data);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((PolyfillModule) obj);
        }

        public override int GetHashCode()
        {
            return (_data != null ? _data.GetHashCode() : 0);
        }
    }
}