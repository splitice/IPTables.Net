using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.Helpers;

namespace IPTables.Net.Iptables.Modules.Polyfill
{
    public class PolyfillModule : ModuleBase, IIpTablesModule, IEquatable<PolyfillModule>
    {
        private readonly Dictionary<String, List<String>> _data = new Dictionary<String, List<String>>();
        private readonly Dictionary<String, bool> _not = new Dictionary<String, bool>();
        

        public PolyfillModule(int version) : base(version)
        {
        }

        public bool Equals(PolyfillModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            if (_data.Count != other._data.Count || _data.Keys.Except(other._data.Keys).Any()) return false;
            return _data.All(thisPair => thisPair.Value.SequenceEqual(other._data[thisPair.Key]));
        }

        public bool NeedsLoading
        {
            get { return true; }
        }

        public int Feed(RuleParser parser, bool not)
        {
            String current = parser.GetCurrentArg();
            _data.Add(current, new List<string> { current });
            _not[current] = not;
            for (int i = 1; i < parser.GetRemainingArgs(); i++)
            {
                string arg = parser.GetNextArg(i);
                if (arg[0] == '-')
                {
                    return i - 1;
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
                if (_not[pair.Key])
                {
                    sb.Append("! ");
                }
                sb.Append(pair.Key);
                sb.Append(" ");
                foreach (string a in pair.Value)
                {
                    sb.Append(ShellHelper.EscapeArguments(a));
                    sb.Append(" ");
                }
            }

            return sb.ToString().TrimEnd(new[] {' '});
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

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((PolyfillModule) obj);
        }

        public override int GetHashCode()
        {
            return (_data != null ? _data.GetHashCode() : 0);
        }
    }
}