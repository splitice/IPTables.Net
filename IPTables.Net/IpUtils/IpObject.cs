using System;
using System.Collections.Generic;

namespace IPTables.Net.IpUtils
{
    public class IpObject
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
    }
}
