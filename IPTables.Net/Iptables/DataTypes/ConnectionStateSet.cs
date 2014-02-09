using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Iptables.DataTypes
{
    public class ConnectionStateSet
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
    }
}
