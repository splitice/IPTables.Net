using System;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.IpSet.Parser
{
    class IpSetSetParser
    {
        private readonly string[] _arguments;
        public int Position = 0;
        private IpSetSet _set;

        public IpSetSetParser(string[] arguments, IpSetSet set)
        {
            _arguments = arguments;
            _set = set;
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
        public int FeedToSkip(int position, bool first)
        {
            Position = position;
            String option = GetCurrentArg();

            if (first)
            {
                _set.InternalName = option;
                _set.Type = IpSetTypeHelper.StringToType(GetNextArg());
                return 1;
            }

            switch (option)
            {
                case "timeout":
                    _set.Timeout = int.Parse(GetNextArg());
                    break;
                case "family":
                    _set.Family = GetNextArg();
                    break;
                case "hashsize":
                    _set.HashSize = int.Parse(GetNextArg());
                    break;
                case "maxelem":
                    _set.MaxElem = UInt32.Parse(GetNextArg());
                    break;
                case "range":
                    _set.BitmapRange = PortOrRange.Parse(GetNextArg(), '-');
                    break;
                default:
                    _set.CreateOptions.Add(GetNextArg());
                    return 0;
            }

            return 1;
        }
    }
}
