using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Sockets;
using System.Reflection.Emit;
using System.Text;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.DataTypes;
using IPTables.Net.Iptables.IpSet.Parser;
using IPTables.Net.Supporting;

namespace IPTables.Net.Iptables.IpSet
{
    /// <summary>
    /// A "entry" in an IPSet "set"
    /// </summary>
    public class IpSetEntry
    {
        #region Fields

        private string _protocol;
        private int _port;
        private string _mac;
        private IpSetSet _set;
        private int _timeout;

        #endregion


        #region Properties

        public IpCidr Cidr { get; set; }
        public IpCidr Cidr2 { get; set; }

        public string Protocol
        {
            get => _protocol;
            set => _protocol = value;
        }

        public int Port
        {
            get => _port;
            set => _port = value;
        }

        public string Mac
        {
            get => _mac;
            set => _mac = value;
        }

        public IpSetSet Set
        {
            get => _set;
            internal set => _set = value;
        }

        public int Timeout
        {
            get => _timeout;
            set => _timeout = value;
        }

        #endregion

        #region Constructor

        public IpSetEntry(IpSetSet set, IpCidr? cidr = null, string protocol = null, int port = -1, string mac = null)
        {
            _set = set;
            Cidr = cidr.HasValue ? cidr.Value : IpCidr.Any;
            _protocol = protocol;
            _port = port;
            _mac = mac;
        }

        #endregion

        public string GetKeyCommand()
        {
            var parts = new List<string>();
            if (Cidr.Prefix != 0) parts.Add(Cidr.ToString());
            if (_mac != null) parts.Add(_mac);
            if (_port != -1)
            {
                if (_protocol != null)
                    parts.Add(_protocol + ":" + _port);
                else
                    parts.Add(_port.ToString());
            }

            if (Cidr2.Prefix != 0) parts.Add(Cidr2.ToString());
            if (parts.Count == 0) throw new IpTablesNetException("Invalid IpSet entry, no parts to key");

            return string.Join(",", parts.ToArray());
        }

        protected bool Equals(IpSetEntry other)
        {
            return _set.Equals(other.Set) && KeyEquals(other) && other.Timeout == _timeout;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((IpSetEntry) obj);
        }


        public static IpSetEntry ParseFromParts(IpSetSet set, string value)
        {
            var entry = new IpSetEntry(set);
            IpSetEntryParser.ParseEntry(entry, value);
            return entry;
        }

        public static IpSetEntry Parse(string command, IpSetSets sets, int startOffset = 0)
        {
            var parts = ArgumentHelper.SplitArguments(command);
            return Parse(parts, sets, startOffset);
        }

        public static IpSetEntry Parse(string[] arguments, IpSetSets sets, int startOffset = 0)
        {
            if (arguments.Length < 2 + startOffset) return null;

            try
            {
                var entry = new IpSetEntry(null);
                var parser = new IpSetEntryParser(arguments, entry, sets);

                for (var i = startOffset; i < arguments.Length; i++) i += parser.FeedToSkip(i, i == startOffset);

                return entry;
            }
            catch (Exception ex)
            {
                throw new IpTablesNetException(
                    string.Format("Failed to parse {0}", string.Join(" ", arguments.Skip(startOffset))), ex);
            }
        }

        public bool KeyEquals(IpSetEntry other, bool cidr = true)
        {
            var r = _port == other._port && (!cidr || Cidr.Equals(other.Cidr)) && Cidr2.Equals(other.Cidr2) &&
                    _mac == other._mac;
            if (!r)
                return false;

            return _protocol == other._protocol;
        }

        public string GetFullCommand(string command = "add")
        {
            var ret = string.Format("{0} {1} {2}", command, Set.Name, GetKeyCommand());
            if (_timeout != 0) ret += " timeout " + _timeout;

            return ret;
        }
    }
}