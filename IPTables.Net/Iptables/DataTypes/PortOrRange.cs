using System;

namespace IPTables.Net.Iptables.DataTypes
{
    public struct PortOrRange
    {
        public static PortOrRange Any = new PortOrRange(0, 0, ':');
        private readonly uint _lowerPort;
        private readonly char _splitChar;
        private readonly uint _upperPort;

        public PortOrRange(uint lowerPort, uint upperPort, char splitChar = ':')
        {
            _lowerPort = lowerPort;
            _upperPort = upperPort;
            _splitChar = splitChar;
        }

        public PortOrRange(uint lowerPort, char splitChar = ':')
        {
            _upperPort = _lowerPort = lowerPort;
            _splitChar = splitChar;
        }

        public uint UpperPort
        {
            get { return _upperPort; }
        }

        public uint LowerPort
        {
            get { return _lowerPort; }
        }

        public override String ToString()
        {
            if (LowerPort == UpperPort)
            {
                return LowerPort.ToString();
            }

            return String.Format("{0}{2}{1}", LowerPort, UpperPort, _splitChar);
        }

        public static PortOrRange Parse(string getNextArg, char splitChar)
        {
            string[] split = getNextArg.Split(new[] {splitChar});
            if (split.Length == 1)
            {
                return new PortOrRange(uint.Parse(split[0]), splitChar);
            }

            return new PortOrRange(uint.Parse(split[0]), uint.Parse(split[1]), splitChar);
        }
    }
}