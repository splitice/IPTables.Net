using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.IpSet.Parser
{
    internal class IpSetEntryParser
    {
        private readonly string[] _arguments;
        private IpSetEntry _entry;
        private IpSetSets _sets;
        private bool _hasKey;

        public IpSetEntryParser(string[] arguments, IpSetEntry entry, IpSetSets sets)
        {
            _arguments = arguments;
            _entry = entry;
            _sets = sets;
        }

        public string GetCurrentArg(int position)
        {
            return _arguments[position];
        }

        public string GetNextArg(int position, int offset = 1)
        {
            if (position + offset >= _arguments.Length) throw new IpTablesNetException("Missing value for " + _arguments[position]);
            return _arguments[position + offset];
        }

        /// <summary>
        /// Parse an entry for type
        /// </summary>
        /// <param name="entry"></param>
        /// <param name="value"></param>
        public static void ParseEntry(IpSetEntry entry, string value)
        {
            var typeComponents = entry.Set.TypeComponents;
            var optionComponents = value.Split(new char[] {','});
            if (optionComponents.Length != typeComponents.Length) throw new IpTablesNetException("Invalid entry tuple arity");

            for (var i = 0; i < optionComponents.Length; i++)
                switch (typeComponents[i])
                {
                    case "ip":
                        if (entry.Cidr.Prefix == 0) entry.Cidr = IpCidr.Parse(optionComponents[i]);
                        else entry.Cidr2 = IpCidr.Parse(optionComponents[i]);
                        break;
                    case "net":
                        entry.Cidr = IpCidr.Parse(optionComponents[i]);
                        var network = entry.Cidr.GetIPNetwork();
                        if (!Equals(network.Network, entry.Cidr.Address))
                            entry.Cidr = new IpCidr(network.Network, entry.Cidr.Prefix);
                        break;
                    case "flag":
                    case "port":
                        var s = optionComponents[i].Split(':');
                        if (s.Length == 1)
                        {
                            entry.Port = ushort.Parse(s[0]);
                        }
                        else
                        {
                            entry.Protocol = s[0].ToLowerInvariant();
                            entry.Port = ushort.Parse(s[1]);
                        }

                        break;
                    case "mac":
                        entry.Mac = optionComponents[i];
                        break;
                }
        }

        /// <summary>
        /// Consume arguments
        /// </summary>
        /// <param name="position">The position to parse</param>
        /// <returns>number of arguments consumed</returns>
        public int FeedToSkip(int position, bool first)
        {
            var option = GetCurrentArg(position);

            if (first)
            {
                var set = _sets.GetSetByName(option);
                if (set == null) throw new IpTablesNetException($"The set {option} does not exist");
                _entry.Set = set;
            }
            else if (option == "timeout")
            {
                _entry.Timeout = int.Parse(GetNextArg(position));
                return 1;
            }
            else if (option == "packets" || option == "bytes")
            {
                // Counters are observational metadata, not part of an entry key.
                ulong.Parse(GetNextArg(position));
                return 1;
            }
            else if (_hasKey)
                throw new IpTablesNetException("Unknown entry option: " + option);
            else
            {
                ParseEntry(_entry, option);
                _hasKey = true;
            }

            return 0;
        }
    }
}