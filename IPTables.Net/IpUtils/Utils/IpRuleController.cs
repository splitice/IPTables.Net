using System.Collections.Generic;
using SystemInteract;

namespace IPTables.Net.IpUtils.Utils
{
    class IpRuleController: IpController
    {
        public IpRuleController(ISystemFactory system) : base("rule", system)
        {
        }

        public List<IpObject> GetAll()
        {
            List<IpObject> r = new List<IpObject>();
            var ret = Command("show");
            var lines = ret[0].Trim().Split('\n');
            foreach (var line in lines)
            {
                var l = line.Trim();
                var obj = ParseObject(l, "pref", new[] { ':' });
                if (obj != null)
                {
                    r.Add(obj);
                }
            }
            return r;
        }

        public override void Delete(IpObject obj)
        {
            if (obj.Pairs.ContainsKey("pref"))
            {
                var ipobj = new IpObject();
                ipobj.Pairs.Add("pref",obj.Pairs["pref"]);
                base.Delete(ipobj);
                return;
            }
            base.Delete(obj);
        }
    }
}
