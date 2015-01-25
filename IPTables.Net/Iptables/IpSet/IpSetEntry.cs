using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.IpSet
{
    class IpSetEntry
    {
        private IpCidr _cidr;
        private String _protocol;
        private ushort _port;
        private String _mac;

        public IpCidr Cidr
        {
            get { return _cidr; }
            set { _cidr = value; }
        }

        public string Protocol
        {
            get { return _protocol; }
            set { _protocol = value; }
        }

        public ushort Port
        {
            get { return _port; }
            set { _port = value; }
        }

        public string Mac
        {
            get { return _mac; }
            set { _mac = value; }
        }

        public IpSetEntry(IpCidr? cidr = null, string protocol = null, ushort port = 0, string mac = null)
        {
            _cidr = cidr.HasValue?cidr.Value:IpCidr.Any;
            _protocol = protocol;
            _port = port;
            _mac = mac;
        }

        public String GetKey()
        {
            List<String> parts = new List<string>();
            if (_cidr != null)
            {
                parts.Add(_cidr.ToString());
            }
            if (parts != null)
            {
                parts.Add(_mac);
            }
            if (_protocol != null && _port != null)
            {
                parts.Add(_protocol + ":" + _port);
            }
            if (parts.Count == 0)
            {
                throw new Exception("Invalid IpSet entry, no parts to key");
            }

            return String.Join(",", parts.ToArray());
        }

        protected bool Equals(IpSetEntry other)
        {
            return _cidr.Equals(other._cidr) && string.Equals(_protocol, other._protocol) && _port == other._port && string.Equals(_mac, other._mac);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((IpSetEntry) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hashCode = _cidr.GetHashCode();
                hashCode = (hashCode*397) ^ (_protocol != null ? _protocol.GetHashCode() : 0);
                hashCode = (hashCode*397) ^ _port.GetHashCode();
                hashCode = (hashCode*397) ^ (_mac != null ? _mac.GetHashCode() : 0);
                return hashCode;
            }
        }

        public IpSetEntry FromEntry(String command, IpSetType type, IpSetSet set)
        {
            var parts = command.Split(new char[] {' '});

            if (parts.Length < 3)
            {
                return null;
            }

            if (parts[0] != "add")
            {
                return null;
            }

            String name = parts[1];
            Debug.Assert(set.Name == name);

            var key = parts[2].Split(new[] {','});

            var ip = IpCidr.Parse(key[0]);
            ushort port = 0;
            String protocol = null;
            if (key.Length != 1)
            {
                var s = key[1].Split(new []{':'});
                port = ushort.Parse(s[0]);
                protocol = s[1];
            }

            return new IpSetEntry(ip, protocol, port);
        }
    }
}
