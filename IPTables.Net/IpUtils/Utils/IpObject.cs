using System;
using System.Collections.Generic;
using System.Linq;

namespace IPTables.Net.IpUtils.Utils
{
    public class IpObject : IEquatable<IpObject>
    {
        public Dictionary<String, String> Pairs = new Dictionary<string, string>();
        public HashSet<String> Singles = new HashSet<string>();

        public IpObject Clone()
        {
            return new IpObject{Pairs = new Dictionary<string, string>(Pairs), Singles = new HashSet<string>(Singles)};
        }

        public T GetNamed<T>(String key, Func<String,T> converter)
        {
            return converter(Pairs[key]);
        }

        public bool Equals(IpObject other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Pairs.OrderBy((a) => a.GetHashCode()).SequenceEqual(other.Pairs.OrderBy((a) => a.GetHashCode())) && Singles.SetEquals(other.Singles);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((IpObject) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return Singles.OfType<object>().Union(Pairs.OfType<object>()).OrderBy((a) => a.GetHashCode()).Aggregate(13, (current, m) => current * 397 + m.GetHashCode());
            }
        }
    }
}
