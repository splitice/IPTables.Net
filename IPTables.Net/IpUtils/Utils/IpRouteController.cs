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

        public List<IpObject> GetAll(String table = "default")
        {
            List<IpObject> r = new List<IpObject>();
            var ret = Command("show", "table", table);
            var lines = ret[0].Trim().Split('\n');
            foreach (var line in lines)
            {
                var l = line.Trim();
                var obj = ParseObject(l, "from");
                if (obj != null)
                {
                    r.Add(obj);
                }
            }
            return r;
        } 
    }
}
