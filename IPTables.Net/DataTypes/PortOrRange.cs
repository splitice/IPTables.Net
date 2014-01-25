using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;


namespace IPTables.Net.DataTypes
{
    public struct PortOrRange
    {
        private readonly uint _lowerPort;
        private readonly uint _upperPort;
        public static PortOrRange Any = new PortOrRange(0, 0);

        public PortOrRange(uint lowerPort, uint upperPort)
        {
            _lowerPort = lowerPort;
            _upperPort = upperPort;
        }

        public PortOrRange(uint lowerPort)
        {
            _upperPort = _lowerPort = lowerPort;
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

            return String.Format("{0}:{1}", LowerPort.ToString(), UpperPort.ToString());
        }

        public static PortOrRange Parse(string getNextArg)
        {
            var split = getNextArg.Split(new char[] {':'});
            if (split.Length == 1)
            {
                return new PortOrRange(uint.Parse(split[0]));
            }

            return new PortOrRange(uint.Parse(split[0]), uint.Parse(split[1]));
        }
    }
}
