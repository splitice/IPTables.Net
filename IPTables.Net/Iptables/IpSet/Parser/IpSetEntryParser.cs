using System;
using System.Linq;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.IpSet.Parser
{
    class IpSetEntryParser
    {
        private readonly string[] _arguments;
        public int Position = 0;
        private IpSetEntry _entry;
        private IpSetSets _sets;

        public IpSetEntryParser(string[] arguments, IpSetEntry entry, IpSetSets sets)
        {
            _arguments = arguments;
            _entry = entry;
            _sets = sets;
        }

        public string GetCurrentArg()
        {
            return _arguments[Position];
        }

        public string GetNextArg(int offset = 1)
        {
            return _arguments[Position + offset];
        }

        public int GetRemainingArgs()
        {
            return _arguments.Length - Position - 1;
        }

        /// <summary>
        /// Consume arguments
        /// </summary>
        /// <param name="position">Rhe position to parse</param>
        /// <returns>number of arguments consumed</returns>
        public int FeedToSkip(int position)
        {
            Position = position;
            String option = GetCurrentArg();

            if (position == 0)
            {
                var set = _sets.GetSetByName(option);
                if (set == null)
                {
                    throw new IpTablesNetException(String.Format("The set {0} does not exist", option));
                }
                _entry.Set = set;
                set.Entries.Add(_entry);
            }
            else
            {
                var type = _entry.Set.Type;
                var typeComponents = IpSetTypeHelper.TypeComponents(IpSetTypeHelper.TypeToString(type)).ToArray();
                var optionComponents = option.Split(new char[] {','});

                if (typeComponents.Length != optionComponents.Length)
                {
                    throw new IpTablesNetException("Missmatch in ipset entry component parts");
                }

                for (int i = 0; i < optionComponents.Length; i++)
                {
                    switch (typeComponents[i])
                    {
                        case "ip":
                            _entry.Cidr = IpCidr.Parse(optionComponents[i]);
                            break;
                        case "port":
                            _entry.Port = ushort.Parse(optionComponents[i]);
                            break;
                        case "mac":
                            _entry.Mac = optionComponents[i];
                            break;
                        case "protocol":
                            _entry.Protocol = optionComponents[i];
                            break;
                    }
                }

            }
            return 0;
        }
    }
}
