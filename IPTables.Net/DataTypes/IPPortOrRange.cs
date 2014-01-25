using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;


namespace IPTables.Net.DataTypes
{
    public struct IPPortOrRange
    {
        private IPAddress _lowerAddress;
        private IPAddress _upperAddress;
        private PortOrRange _port;

        public IPPortOrRange(IPAddress lowerAddress, IPAddress upperAddress, PortOrRange port)
        {
            _lowerAddress = lowerAddress;
            _upperAddress = upperAddress;
            _port = port;
        }

        public IPPortOrRange(IPAddress lowerAddress, PortOrRange port)
        {
            _upperAddress = _lowerAddress = lowerAddress;
            _port = port;
        }

        public override String ToString()
        {
            if (_lowerAddress.Equals(_upperAddress))
            {
                return _lowerAddress.ToString()+":"+_port;
            }

            return String.Format("{0}-{1}:{2}", _lowerAddress.ToString(), _upperAddress.ToString(), _port);
        }

        public static IPPortOrRange Parse(string getNextArg)
        {
            throw new NotImplementedException();
            var split = getNextArg.Split(new char[] {':'});
            if (split.Length == 1)
            {
                return new IPPortOrRange();
            }

           
        }
    }
}
