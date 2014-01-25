using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;


namespace IPTables.Net.DataTypes
{
    public struct PortOrRange
    {
        private uint _lowerPort;
        private uint _upperPort;

        public PortOrRange(uint lowerPort, uint upperPort)
        {
            _lowerPort = lowerPort;
            _upperPort = upperPort;
        }

        public PortOrRange(uint lowerPort)
        {
            _upperPort = _lowerPort = lowerPort;
        }

        public override String ToString()
        {
            if (_lowerPort == _upperPort)
            {
                return _lowerPort.ToString();
            }

            return String.Format("{0}:{1}", _lowerPort.ToString(), _upperPort.ToString());
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
