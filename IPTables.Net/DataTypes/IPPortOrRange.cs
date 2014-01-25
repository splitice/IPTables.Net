using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;


namespace IPTables.Net.DataTypes
{
    public struct IPPortOrRange
    {
        private readonly IPAddress _lowerAddress;
        private readonly IPAddress _upperAddress;
        private PortOrRange _port;

        public IPPortOrRange(IPAddress lowerAddress, IPAddress upperAddress, PortOrRange port)
        {
            _lowerAddress = lowerAddress;
            _upperAddress = upperAddress;
            _port = port;
        }

        public IPPortOrRange(IPAddress lowerAddress, IPAddress upperAddress)
        {
            _lowerAddress = lowerAddress;
            _upperAddress = upperAddress;
            _port = PortOrRange.Any;
        }

        public IPPortOrRange(IPAddress lowerAddress, PortOrRange port)
        {
            _upperAddress = _lowerAddress = lowerAddress;
            _port = port;
        }

        public IPPortOrRange(IPAddress lowerAddress)
        {
            _upperAddress = _lowerAddress = lowerAddress;
            _port = PortOrRange.Any;
        }

        public IPAddress LowerAddress
        {
            get { return _lowerAddress; }
        }

        public IPAddress UpperAddress
        {
            get { return _upperAddress; }
        }

        private String PortStringRepresentation()
        {
            if (_port.LowerPort == 0 && _port.UpperPort == 0)
            {
                return "";
            }

            return _port.ToString();
        }

        public override String ToString()
        {
            if (LowerAddress.Equals(UpperAddress))
            {
                return LowerAddress.ToString() + ":" + PortStringRepresentation();
            }

            return String.Format("{0}-{1}:{2}", LowerAddress.ToString(), UpperAddress.ToString(), PortStringRepresentation());
        }

        public static IPPortOrRange Parse(string getNextArg)
        {
            var split = getNextArg.Split(new char[] { ':' });
            if (split.Length == 0)
            {
                throw new Exception("Error");
            }

            var splitIp = split[0].Split(new char[] { '-' });

            IPAddress lowerIp = IPAddress.Parse(splitIp[0]);
            IPAddress upperIp;
            if (splitIp.Length == 1)
            {
                upperIp = lowerIp;
            }
            else
            {
                upperIp = IPAddress.Parse(splitIp[1]);
            }

            if (split.Length == 1)
            {
                return new IPPortOrRange(lowerIp, upperIp);
            }
            else
            {
                return new IPPortOrRange(lowerIp, upperIp, PortOrRange.Parse(split[1]));
            }
        }
    }
}
