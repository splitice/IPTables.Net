using System;
using System.Collections.Generic;
using SystemInteract;
using IPTables.Net.Exceptions;

namespace IPTables.Net.IpUtils.Utils
{
    public class IpRouteController : IpController
    {
        public IpRouteController(ISystemFactory system) : base("route", system)
        {
        }

        protected override bool IsSingle(string key)
        {
            if (key == "onlink" || key == "pervasive" || key == "broadcast" || key == "unreachable") return true;
            return base.IsSingle(key);
        }

        public List<IpObject> GetAll(String table = null)
        {
            List<IpObject> r = new List<IpObject>();
            var args = table == null ? new string[0] : new string[] { "table", table };
            var ret = Command("show", args);
            var lines = ret[0].Trim().Split('\n');
            foreach (var line in lines)
            {
                var l = line.Trim();
                IpObject obj;
                try
                {
                    obj = ParseObject(l);
                }
                catch (Exception ex)
                {
                    throw new IpTablesNetException("An exception occured while parsing route: "+ line, ex);
                }
                if (obj != null)
                {
                    if (table != "default" && table != "all")
                    {
                        obj.Pairs.Add("table", table);
                    }
                    r.Add(obj);
                }
            }
            return r;
        }

        public IpObject ParseObject(string str)
        {
            return ParseObject(str, "to");
        }

        protected override IpObject ParseObject(string str, string firstKey, char[] firstTrimChars = null)
        {
            String[] strs = str.Split(new char[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (strs.Length != 0 && strs[0] == "local")
            {
                return base.ParseObject(str, null);
            }
            return base.ParseObject(str, firstKey, firstTrimChars);
        }

        internal override String[] ExportObject(IpObject obj)
        {
            List<String> ret = new List<string>();
            if (obj.Pairs.ContainsKey("to"))
            {
                ret.Add(obj.Pairs["to"]);
            }
            foreach (var kv in obj.Pairs)
            {
                if(kv.Key == "to") continue;
                ret.Add(kv.Key);
                ret.Add(kv.Value);
            }
            ret.AddRange(obj.Singles);
            return ret.ToArray();
        }
    }
}
