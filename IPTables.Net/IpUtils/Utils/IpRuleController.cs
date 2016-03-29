using System;
using System.Collections.Generic;
using SystemInteract;
using IPTables.Net.Exceptions;

namespace IPTables.Net.IpUtils.Utils
{
    public class IpRuleController : IpController
    {
        public IpRuleController(ISystemFactory system) : base("rule", system)
        {
        }

        protected override bool IsSingle(string key)
        {
            if (key == "not") return true;
            return base.IsSingle(key);
        }

        public List<IpObject> GetAll()
        {
            List<IpObject> r = new List<IpObject>();
            var ret = Command("show");
            var lines = ret[0].Trim().Split('\n');
            foreach (var line in lines)
            {
                var l = line.Trim();
                //Console.WriteLine(l);
                IpObject obj;
                try { 
                    obj = ParseObject(l, "pref", new[] { ':' });
                }
                catch (Exception ex)
                {
                    throw new IpTablesNetException("An exception occured while parsing rule: " + line, ex);
                }
                if (obj != null)
                {
                    r.Add(obj);
                }
            }
            return r;
        }

        internal override string[] ExportObject(IpObject obj)
        {
            var ret = new List<string>(base.ExportObject(obj));
            if (!obj.Pairs.ContainsKey("from"))
            {
                ret.Add("from");
                ret.Add("all");
            }
            return ret.ToArray();
        }
    }
}
