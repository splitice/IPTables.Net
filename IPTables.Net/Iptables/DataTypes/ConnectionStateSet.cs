using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Iptables.DataTypes
{
    public class ConnectionStateSet : IEquatable<ConnectionStateSet>
    {
        private readonly HashSet<ConnectionState> _states = new HashSet<ConnectionState>();

        public IEnumerable<ConnectionState> States
        {
            get
            {
                return _states;
            }
        }

        public ConnectionStateSet(IEnumerable<ConnectionState> states)
        {
            foreach (var s in states)
            {
                _states.Add(s);
            }
        }

        public override String ToString()
        {
            return String.Join(",",_states.Select(ConnectionStateHelper.GetString).ToArray());
        }

        public static ConnectionStateSet Parse(string stringRepresentation)
        {
            var split = stringRepresentation.Split(new char[] {','});
            return new ConnectionStateSet(split.Select(ConnectionStateHelper.FromString));
        }

        public bool Equals(ConnectionStateSet other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return _states.SetEquals(other._states);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((ConnectionStateSet) obj);
        }

        public override int GetHashCode()
        {
            return (_states != null ? _states.GetHashCode() : 0);
        }
    }
}
