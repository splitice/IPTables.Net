using System;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using IPTables.Net.Exceptions;

namespace IPTables.Net.Iptables.DataTypes
{
    public struct IPPortOrRange
    {
        private static Regex ParsePattern = new Regex(@"(?:(?:\[(?<ip1_1>[0-9a-fA-f\:]+)\]-)?\[(?<ip2_1>[0-9a-fA-f\:]+)\](?::(?<port_1>[0-9\-]+))?)|(?:(?:(?<ip1_2>[0-9\.]+)-)?(?<ip2_2>[0-9\.]+)(?::(?<port_2>[0-9\-]+))?)|(?:(?:(?<ip1_3>[0-9a-fA-f\:]+)-)?(?<ip2_3>[0-9a-fA-f\:]+))");
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

        public PortOrRange Port
        {
            get { return _port; }
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
            string strPort = PortStringRepresentation();
            if (LowerAddress.Equals(UpperAddress))
            {
                if (strPort.Length == 0)
                {
                    return LowerAddress.ToString();
                }
                return LowerAddress + ":" + PortStringRepresentation();
            }

            if (strPort.Length == 0)
            {
                return String.Format("{0}-{1}", FormatIp(LowerAddress), FormatIp(UpperAddress));
            }
            return String.Format("{0}-{1}:{2}", FormatIp(LowerAddress), FormatIp(UpperAddress), strPort);
        }

        private string FormatIp(IPAddress ip)
        {
            if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            {
                return "["+ip+"]";
            }
            return ip.ToString();
        }

        public static IPPortOrRange Parse(string getNextArg)
        {
            var match = ParsePattern.Match(getNextArg);

            if (!match.Success)
            {
                throw new ArgumentException("Invalid IP port or range format");
            }

            IPAddress lowerIp = null;
            IPAddress upperIp = null;
            String port = null;

            for (int i = 0; i<match.Groups.Count; i++)
            {
                var g = match.Groups[i];
                if (g.Value == "") continue;

                var name = ParsePattern.GroupNameFromNumber(i);
                if (name == "ip1_1" || name == "ip1_2" || name == "ip1_3")
                {
                    lowerIp = IPAddress.Parse(g.Value);
                }
                else if (name == "ip2_1" || name == "ip2_2" || name == "ip2_3")
                {
                    upperIp = IPAddress.Parse(g.Value);
                }
                else if (name == "port_1" || name == "port_2" || name == "port_3")
                {
                    port = g.Value;
                }
            }

            if (lowerIp == null)
            {
                lowerIp = upperIp;
            }

            if (port == null)
            {
                return new IPPortOrRange(lowerIp, upperIp);
            }
            return new IPPortOrRange(lowerIp, upperIp, PortOrRange.Parse(port, '-'));
        }
    }
}