using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.DataTypes;
using IPTables.Net.Iptables.Helpers;

namespace IPTables.Net.Iptables.Modules.StringMatch
{
    public class StringModule : ModuleBase, IEquatable<StringModule>, IIpTablesModule
    {
        public enum Strategy
        {
            BoyerMoore,
            KnuthPrattMorris
        }

        public enum NotationTypes
        {
            Plain,
            Hex
        }

        private const string OptionAlgorithmLong = "--algo";
        private const string OptionFromLong = "--from";
        private const string OptionToLong = "--to";
        private const string OptionStringLong = "--string";
        private const string OptionHexStringLong = "--hex-string";

        public Strategy Algorithm;
        public int From = 0;
        public int To = 0;
        public NotationTypes Notation = NotationTypes.Plain;
        public ValueOrNot<string> Pattern;

        public StringModule(int version) : base(version)
        {
        }

        public void SetHexString(byte[] pattern, bool not = false)
        {
            var hex = new StringBuilder();
            hex.Append("|");
            foreach (var b in pattern)
                hex.AppendFormat("{0:x2}", b);

            hex.Append("|");
            SetHexString(hex.ToString());
        }

        public void SetHexString(string pattern, bool not = false)
        {
            pattern = pattern.Replace(" ", "");
            Pattern = new ValueOrNot<string>(pattern, not);
            Notation = NotationTypes.Hex;
        }

        public int Feed(CommandParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionAlgorithmLong:
                    var alg = parser.GetNextArg();
                    if (alg == "bm")
                        Algorithm = Strategy.BoyerMoore;
                    else if (alg == "kmp")
                        Algorithm = Strategy.KnuthPrattMorris;
                    else
                        throw new IpTablesNetException("Unknown algorithm: " + alg);
                    return 1;
                case OptionFromLong:
                    From = int.Parse(parser.GetNextArg());
                    return 1;
                case OptionToLong:
                    To = int.Parse(parser.GetNextArg());
                    return 1;
                case OptionStringLong:
                    Pattern = new ValueOrNot<string>(parser.GetNextArg(), not);
                    return 1;
                case OptionHexStringLong:
                    SetHexString(parser.GetNextArg(), not);
                    return 1;
            }

            return 0;
        }

        public bool NeedsLoading => true;

        public string GetRuleString()
        {
            var ret = "--alg ";
            if (Algorithm == Strategy.BoyerMoore)
                ret += "bm";
            else
                ret += "kmp";

            if (From != 0) ret += " --from " + From;

            if (To != 0) ret += " --to " + To;

            if (Notation == NotationTypes.Hex)
                ret += " " + Pattern.ToOption(OptionHexStringLong);
            else
                ret += " " + Pattern.ToOption(OptionStringLong);

            return ret;
        }

        public static HashSet<string> GetOptions()
        {
            var options = new HashSet<string>
            {
                OptionAlgorithmLong,
                OptionFromLong,
                OptionToLong,
                OptionStringLong,
                OptionHexStringLong
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("string", typeof(StringModule), GetOptions);
        }

        public bool Equals(StringModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Algorithm == other.Algorithm && From == other.From && To == other.To && Notation == other.Notation &&
                   Equals(Pattern, other.Pattern);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((StringModule) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = (int) Algorithm;
                hashCode = (hashCode * 397) ^ From;
                hashCode = (hashCode * 397) ^ To;
                hashCode = (hashCode * 397) ^ (int) Notation;
                hashCode = (hashCode * 397) ^ Pattern.GetHashCode();
                return hashCode;
            }
        }
    }
}