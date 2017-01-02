using System;
using System.Collections.Generic;
using System.Linq;
using SystemInteract;
using IPTables.Net.Exceptions;

namespace IPTables.Net.IpUtils.Utils
{
    public abstract class IpController
    {
        protected ISystemFactory _system;
        protected String _module;

        public IpController(String module, ISystemFactory system)
        {
            _module = module;
            _system = system;
        }

        protected virtual bool IsSingle(String key)
        {
            return false;
        }

        internal virtual String[] ExportObject(IpObject obj)
        {
            var ret = new List<string>(obj.Singles);
            foreach (var kv in obj.Pairs)
            {
                ret.Add(kv.Key);
                ret.Add(kv.Value);
            }
            return ret.ToArray();
        }

        internal IpObject ParseObjectInternal(String str, String firstKey, char[] firstTrimChars = null)
        {
            return ParseObject(str, firstKey, firstTrimChars);
        }

        public virtual IpObject ParseObject(String str, String firstKey, char[] firstTrimChars = null)
        {
            IpObject ret = new IpObject();
            String[] strs = str.Split(new char[] {' ','\t'}, StringSplitOptions.RemoveEmptyEntries);
            if (strs.Length == 0)
            {
                return null;
            }
            int i = 0;
            for (; i < strs.Length; i++)
            {
                var k = strs[i];
                if (IsSingle(k))
                {
                    ret.Singles.Add(k);
                }
                else
                {
                    break;
                }
            }
            if (firstKey != null)
            {
                var v = strs[i];
                if (firstTrimChars != null)
                {
                    v = v.TrimEnd(firstTrimChars);
                }
                ret.Pairs.Add(firstKey, v);
                i++;
            }
            for (; i < strs.Length; i++)
            {
                var k = strs[i];
                if (IsSingle(k))
                {
                    ret.Singles.Add(k);
                }
                else if (i + 1 != strs.Length)
                {
                    ret.Pairs.Add(k,strs[i+1]);
                    i++;
                }
                else
                {
                    //Console.WriteLine("{0} {1}",ret.Singles.Count,string.Join(", ",ret.Pairs.Select((a)=>a.Key + ":" + a.Value)));
                    throw new IpTablesNetException(String.Format("Insufficient values to parse: {0}", k));
                }
            }
            return ret;
        }

        protected string[] Command(String command, params String[] args)
        {
            String cmd = String.Format("{0} {1} {2}", _module, command, String.Join(" ", args));
            using (var process = _system.StartProcess("ip", cmd.TrimEnd()))
            {
                String output, error;
                ProcessHelper.ReadToEnd(process, out output, out error);
                return new string[] {output.Trim(), error.Trim()};
            }
        }

        public virtual void Add(params String[] args)
        {
            var ret = Command("add", args);
            if (ret[0].Length != 0)
            {
                throw new IpControllerException(String.Format("Unable to add {0} \"{1}\" occured while processing: {2}",_module,ret[0],string.Join(" ", args)));
            }
            if (ret[1].Length != 0)
            {
                throw new IpControllerException(String.Format("Unable to add {0} error \"{1}\" occured while processing: {2}", _module, ret[0], string.Join(" ", args)));
            }
        }

        public virtual void Add(IpObject obj)
        {
            Add(ExportObject(obj));
        }

        public virtual void Delete(params String[] args)
        {
            var ret = Command("delete", args);
            if (ret[0].Length != 0)
            {
                throw new IpControllerException(String.Format("Unable to delete {0} \"{1}\" occured while processing: {2}", _module, ret[0], string.Join(" ", args)));
            }
            if (ret[1].Length != 0)
            {
                throw new IpControllerException(String.Format("Unable to delete {0} error \"{1}\" occured while processing: {2}", _module, ret[0], string.Join(" ", args)));
            }
        }

        public virtual void Delete(IpObject obj)
        {
            Delete(ExportObject(obj));
        }
    }
}
