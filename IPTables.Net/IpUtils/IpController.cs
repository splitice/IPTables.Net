using System;
using System.Collections.Generic;
using SystemInteract;

namespace IPTables.Net.IpUtils
{
    public abstract class IpController
    {
        private ISystemFactory _system;
        private String _module;

        public IpController(String module, ISystemFactory system)
        {
            _module = module;
            _system = system;
        }

        protected virtual bool IsSingle(String key)
        {
            return false;
        }

        protected virtual String[] ExportObject(IpObject obj)
        {
            var ret = new List<string>(obj.Singles);
            foreach (var kv in obj.Pairs)
            {
                ret.Add(kv.Key);
                ret.Add(kv.Value);
            }
            return ret.ToArray();
        }

        protected IpObject ParseObject(String str, String firstKey, char[] firstTrimChars = null)
        {
            IpObject ret = new IpObject();
            String[] strs = str.Split(new char[] {' '}, StringSplitOptions.RemoveEmptyEntries);
            if (strs.Length == 0)
            {
                return null;
            }
            int i = 0;
            if (firstKey != null && strs[0] != firstKey)
            {
                if (i != strs.Length)
                {
                    var v = strs[i + 1];
                    if (firstTrimChars != null)
                    {
                        v = v.TrimEnd(firstTrimChars);
                    }
                    ret.Pairs.Add(firstKey, v);
                    i++;
                }
                else
                {
                    throw new Exception("Insufficient values to parse");
                }
            }
            for (; i < strs.Length; i++)
            {
                var k = strs[i];
                if (IsSingle(k))
                {
                    ret.Singles.Add(k);
                }
                else if (i != strs.Length)
                {
                    ret.Pairs.Add(k,strs[i+1]);
                    i++;
                }
                else
                {
                    throw new Exception("Insufficient values to parse");
                }
            }
            return ret;
        }

        protected string[] Command(String command, params String[] args)
        {
            String cmd = String.Format("{0} {1} {2}", _module, command, String.Join(" ", args));
            var process = _system.StartProcess("ip", cmd);
            String output, error;
            ProcessHelper.ReadToEnd(process, out output, out error);
            return new string[] { output.Trim(), error.Trim() };
        }

        public void Add(params String[] args)
        {
            var ret = Command("add", args);
            if (ret[0].Length != 0)
            {
                throw new Exception(String.Format("Unable to add {0}: {1}",_module,ret[0]));
            }
            if (ret[1].Length != 0)
            {
                throw new Exception(String.Format("Unable to add {0}: {1}", _module, ret[1]));
            }
        }

        public void Add(IpObject obj)
        {
            Add(ExportObject(obj));
        }

        public void Delete(params String[] args)
        {
            var ret = Command("delete", args);
            if (ret[0].Length != 0)
            {
                throw new Exception(String.Format("Unable to delete {0}: {1}", _module, ret[0]));
            }
            if (ret[1].Length != 0)
            {
                throw new Exception(String.Format("Unable to delete {0}: {1}", _module, ret[1]));
            }
        }

        public void Delete(IpObject obj)
        {
            Delete(ExportObject(obj));
        }
    }
}
