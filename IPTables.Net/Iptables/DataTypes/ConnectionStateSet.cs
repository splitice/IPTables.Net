using System;
using System.Collections.Generic;
using System.Linq;

namespace IPTables.Net.Iptables.DataTypes
{
    public class ConnectionStateSet : IEquatable<ConnectionStateSet>
    {
        private readonly HashSet<ConnectionState> _states = new HashSet<ConnectionState>();

        public ConnectionStateSet(IEnumerable<ConnectionState> states)
        {
            foreach (var s in states) _states.Add(s);
        }

        public IEnumerable<ConnectionState> States => _states;

        public bool Equals(ConnectionStateSet other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return _states.SetEquals(other._states);
        }

        public override string ToString()
        {
            return string.Join(",", _states.Select(ConnectionStateHelper.GetString).ToArray());
        }

        public static ConnectionStateSet Parse(string stringRepresentation)
        {
            var split = stringRepresentation.Split(new[] {','});
            return new ConnectionStateSet(split.Select(ConnectionStateHelper.FromString));
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((ConnectionStateSet) obj);
        }

        public override int GetHashCode()
        {
            return _states != null ? _states.GetHashCode() : 0;
        }
    }
}