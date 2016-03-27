using System;
using System.Collections.Generic;
using IPTables.Net.IpUtils.Utils;

namespace IPTables.Net.IpUtils.Sync
{
    public class DefaultIpuSync
    {
        private IpController _controller;
        private Func<IEnumerable<IpObject>> _getter;

        public DefaultIpuSync(IpController controller, Func<IEnumerable<IpObject>> getter)
        {
            _controller = controller;
            _getter = getter;
        }

        public void Sync(IEnumerable<IpObject> with)
        {
            HashSet<IpObject> objects = new HashSet<IpObject>(with);

            foreach (var ipobj in _getter())
            {
                if (!objects.Contains(ipobj))
                {
                    _controller.Delete(ipobj);
                }
                else
                {
                    objects.Remove(ipobj);
                }
            }

            foreach (var ipobj in objects)
            {
                _controller.Add(ipobj);
            }
        }
    }
}
