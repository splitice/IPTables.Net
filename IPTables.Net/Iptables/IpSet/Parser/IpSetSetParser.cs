using System;

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
                _set = new IpSetSet(IpSetTypeHelper.StringToType(GetNextArg()), option, _set.Timeout, _set.Family,
                    _set.System, _set.SyncMode);
                return 1;
            }
            else
            {
                switch (option)
                {
                    case "family":
                        _set.Family = GetNextArg();
                        break;
                    case "hashsize":
                        _set.HashSize = int.Parse(GetNextArg());
                        break;
                    case "maxelem":
                        _set.MaxElem = int.Parse(GetNextArg());
                        break;
                }

                return 1;
            }
        }
    }
}
