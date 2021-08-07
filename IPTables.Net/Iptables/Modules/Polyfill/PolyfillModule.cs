using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.Helpers;
using IPTables.Net.Supporting;

namespace IPTables.Net.Iptables.Modules.Polyfill
{
    public class PolyfillModule : ModuleBase, IIpTablesModule, IEquatable<PolyfillModule>
    {
        private readonly Dictionary<string, List<string>> _data = new Dictionary<string, List<string>>();
        private readonly Dictionary<string, bool> _not = new Dictionary<string, bool>();


        public PolyfillModule(int version) : base(version)
        {
        }

        public bool Equals(PolyfillModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            if (_data.Count != other._data.Count || _data.Keys.Except(other._data.Keys).Any()) return false;
            return _not.All(thisPair => other._not[thisPair.Key] == thisPair.Value) && _data.All(thisPair =>
                thisPair.Value.All((a) => other._data[thisPair.Key].Contains(a)));
        }

        public bool NeedsLoading => true;

        public int Feed(CommandParser parser, bool not)
        {
            var current = parser.GetCurrentArg();
            _data.Add(current, new List<string>());
            _not[current] = not;

            for (var i = 1; i <= parser.GetRemainingArgs(); i++)
            {
                var arg = parser.GetNextArg(i);
                if (arg[0] == '-') return i - 1;
                _data[current].Add(arg);
            }

            return _data[current].Count;
        }

        public string GetRuleString()
        {
            var sb = new StringBuilder();

            foreach (var pair in _data)
            {
                if (_not[pair.Key]) sb.Append("! ");
                sb.Append(pair.Key);
                sb.Append(" ");
                foreach (var a in pair.Value)
                {
                    sb.Append(ShellHelper.EscapeArguments(a));
                    sb.Append(" ");
                }
            }

            return sb.ToString().TrimEnd(new[] {' '});
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetPolyModuleEntryInternal(typeof(PolyfillModule));
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
            return _data != null ? _data.GetHashCode() : 0;
        }
    }
}