using System;

namespace IPTables.Net.Iptables.DataTypes
{
    public struct PortOrRange : IEquatable<PortOrRange>
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

        public uint UpperPort => _upperPort;

        public uint LowerPort => _lowerPort;

        public bool IsRange()
        {
            return _upperPort != _lowerPort;
        }

        public override string ToString()
        {
            if (LowerPort == UpperPort) return LowerPort.ToString();

            return string.Format("{0}{2}{1}", LowerPort, UpperPort, _splitChar);
        }

        public static PortOrRange Parse(string getNextArg, char splitChar)
        {
            var split = getNextArg.Split(new[] {splitChar});
            if (split.Length == 1) return new PortOrRange(uint.Parse(split[0]), splitChar);

            return new PortOrRange(uint.Parse(split[0]), uint.Parse(split[1]), splitChar);
        }

        public bool Equals(PortOrRange other)
        {
            return _lowerPort == other._lowerPort && _upperPort == other._upperPort;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            return obj is PortOrRange && Equals((PortOrRange) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return ((int) _lowerPort * 397) ^ (int) _upperPort;
            }
        }
    }
}