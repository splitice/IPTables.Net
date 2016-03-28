using System;
using System.Collections.Generic;
using SystemInteract;

namespace IPTables.Net.IpUtils.Utils
{
    public class IpRouteController : IpController
    {
        public IpRouteController(ISystemFactory system) : base("rule", system)
        {
        }

        protected override bool IsSingle(string key)
        {
            if (key == "onlink" || key == "pervasive") return true;
            return base.IsSingle(key);
        }

        public List<IpObject> GetAll(String table = "default")
        {
            List<IpObject> r = new List<IpObject>();
            var ret = Command("show", "table", table);
            var lines = ret[0].Trim().Split('\n');
            foreach (var line in lines)
            {
                var l = line.Trim();
                var obj = ParseObject(l, "to");
                if (obj != null)
                {
                    r.Add(obj);
                }
            }
            return r;
        }

        internal override String[] ExportObject(IpObject obj)
        {
            List<String> ret = new List<string>();
            ret.Add(obj.Pairs["to"]);
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
