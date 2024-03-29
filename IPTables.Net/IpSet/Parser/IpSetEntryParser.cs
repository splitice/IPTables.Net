﻿using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.IpSet.Parser
{
    internal class IpSetEntryParser
    {
        private readonly string[] _arguments;
        private IpSetEntry _entry;
        private IpSetSets _sets;

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
                set.Entries.Add(_entry);
            }
            else if (option == "timeout")
            {
                _entry.Timeout = int.Parse(GetNextArg(position));
                return 1;
            }
            else if (option == "packets" || option == "bytes")
            {
                // ignore
                return 1;
            }
            else
            {
                ParseEntry(_entry, option);
            }

            return 0;
        }
    }
}