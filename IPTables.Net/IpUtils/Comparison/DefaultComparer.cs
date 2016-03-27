using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using IPTables.Net.IpUtils.Utils;

namespace IPTables.Net.IpUtils.Comparison
{
    public class DefaultComparer
    {
        private IpController _controller;
        private Func<IEnumerable<IpObject>> _getter;

        public DefaultComparer(IpController controller, Func<IEnumerable<IpObject>> getter)
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
